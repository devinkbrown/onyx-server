// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Standalone strict media recording journal (`ONYXREC1`).
//!
//! Append-only, length-prefixed, transport-neutral packet journal. The
//! writer never inspects RTP/native/WebRTC framing: callers pass an opaque
//! packet payload plus track/timing/keyframe metadata. Packet bytes here are
//! therefore "transport-neutral" — whatever canonical encoded media bytes the
//! pump already validated.
//!
//! File layout (all integers little-endian):
//!   file header `[header_len]u8` (see `encodeHeader`)
//!   frames: `[u32 body_len][body]` repeated until EOF/torn tail
//!     body: seq u64, type u8, track_id u16, flags u8, pts_us i64,
//!           duration_us u32, payload_len u32, payload, crc32c u32, chain [32]u8
//!     crc32c covers seq..payload. chain = SHA-256(prev_chain || seq..payload
//!     || crc32c), or HMAC-SHA-256(key, same) when a MAC key was configured
//!     (header flag `flag_mac_chain`). prev_chain genesis = SHA-256(domain ||
//!     file_header_bytes).
//!
//! Durability / naming contract:
//!   * A segment is written to `rec-<32hex>-s<NNNNNN>.part` (0600, exclusive),
//!     fsynced, then renamed to `.onyxrec`; the parent directory is fsynced
//!     after the rename. Recording ids are random (caller may inject one for
//!     tests/rotation custody). No nick, channel, account, or room string is
//!     ever accepted for a path — the API simply has no such parameter.
//!   * Recovery is torn-tail only: the first incomplete/corrupt frame ends the
//!     valid prefix. Nothing after it is trusted or resynchronised.
//!   * Quota and duration caps are checked before any frame byte is written,
//!     with space reserved for the trailing segment-end frame, so a refused
//!     packet never leaves a partial frame and `finalize` can always fit its
//!     end frame under the caps that admitted the packets.
//!
//! Integration seams are `Queue.tryPushTrack` / `Queue.tryPush`
//! (nonblocking producer side for the media pump), `Writer.drainQueue`
//! (single consumer), `ensurePrivateDir`, `Writer.create/rotate/finalize`,
//! `scan`/`recoverFile`, and `Manifest`/`writeManifestFile`.

const std = @import("std");
const builtin = @import("builtin");
const crc32c_mod = @import("../substrate/crc32c.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const magic = "ONYXREC1";
pub const format_version: u16 = 1;
/// File-header byte length. Frames start exactly at this offset.
pub const header_len: usize = 48;
/// `body_len` field width.
pub const length_len: usize = 4;
/// Fixed frame fields between `body_len` and the payload.
pub const frame_fixed_len: usize = 28;
/// crc32c (4) + chain digest (32) after the payload.
pub const frame_trailer_len: usize = 36;

pub const max_tracks_hard: usize = 32;
pub const max_codec_len: usize = 32;
pub const max_language_len: usize = 8;
pub const max_packet_bytes_hard: u32 = 16 * 1024 * 1024;
pub const recording_id_len: usize = 16;
pub const recording_id_hex_len: usize = recording_id_len * 2;

pub const flag_mac_chain: u32 = 1 << 0;

pub const frame_flag_keyframe: u8 = 1 << 0;
pub const frame_flag_end_of_stream: u8 = 1 << 1;
pub const frame_flag_discontinuity: u8 = 1 << 2;

pub const Error = error{
    InvalidConfig,
    InvalidRecordingId,
    InvalidTrack,
    DuplicateTrack,
    TooManyTracks,
    UnknownTrack,
    TrackKindMismatch,
    InvalidPacket,
    PacketTooLarge,
    OutOfOrderPts,
    SegmentFull,
    QuotaExceeded,
    DurationCapExceeded,
    WriterClosed,
    WriterFailed,
    InvalidHeader,
    UnsupportedVersion,
    UnprotectedDirectory,
    InvalidName,
};

/// Random, path-safe recording identity. Zero is rejected everywhere.
pub const RecordingId = struct {
    bytes: [recording_id_len]u8,

    pub fn random(io: std.Io) RecordingId {
        while (true) {
            var id: RecordingId = undefined;
            io.random(&id.bytes);
            if (!id.isZero()) return id;
        }
    }
    pub fn fromBytes(bytes: [recording_id_len]u8) Error!RecordingId {
        const id: RecordingId = .{ .bytes = bytes };
        if (id.isZero()) return error.InvalidRecordingId;
        return id;
    }
    pub fn isZero(self: RecordingId) bool {
        var acc: u8 = 0;
        for (self.bytes) |b| acc |= b;
        return acc == 0;
    }
    pub fn eql(self: RecordingId, other: RecordingId) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }
    pub fn hex(self: RecordingId) [recording_id_hex_len]u8 {
        return std.fmt.bytesToHex(self.bytes, .lower);
    }
    /// Strict lowercase-hex parse (the only form `hex` emits).
    pub fn parseHex(text: []const u8) Error!RecordingId {
        if (text.len != recording_id_hex_len) return error.InvalidRecordingId;
        var id: RecordingId = undefined;
        const decoded = std.fmt.hexToBytes(&id.bytes, text) catch return error.InvalidRecordingId;
        if (decoded.len != recording_id_len) return error.InvalidRecordingId;
        // Reject uppercase/non-canonical spellings by round-trip comparison.
        if (!std.mem.eql(u8, &id.hex(), text)) return error.InvalidRecordingId;
        if (id.isZero()) return error.InvalidRecordingId;
        return id;
    }
};

pub const TrackKind = enum(u8) {
    audio = 1,
    video = 2,
    screen = 3,
    caption = 4,

    pub fn needsKeyframe(self: TrackKind) bool {
        return self == .video or self == .screen;
    }
    pub fn name(self: TrackKind) []const u8 {
        return @tagName(self);
    }
};

fn validCodec(text: []const u8) bool {
    if (text.len == 0 or text.len > max_codec_len) return false;
    for (text) |b| {
        const ok = (b >= 'a' and b <= 'z') or (b >= 'A' and b <= 'Z') or
            (b >= '0' and b <= '9') or b == '-' or b == '_' or b == '.' or b == '+';
        if (!ok) return false;
    }
    return true;
}
fn validLanguage(text: []const u8) bool {
    if (text.len > max_language_len) return false;
    for (text) |b| {
        const ok = (b >= 'a' and b <= 'z') or (b >= 'A' and b <= 'Z') or
            (b >= '0' and b <= '9') or b == '-';
        if (!ok) return false;
    }
    return true;
}

/// One declared media track. Value type; codec/language are inline buffers.
/// Width/height must both be nonzero for video/screen and zero for
/// audio/caption. `clock_rate` must be nonzero for audio/video/screen
/// (e.g. 48000 / 90000); caption tracks may use 0 (pts is already in µs).
pub const Track = struct {
    id: u16,
    kind: TrackKind,
    clock_rate: u32 = 0,
    width: u32 = 0,
    height: u32 = 0,
    codec_buf: [max_codec_len]u8 = @splat(0),
    codec_len: u8 = 0,
    language_buf: [max_language_len]u8 = @splat(0),
    language_len: u8 = 0,

    /// Builder entry point: checks id/codec/clock immediately. Video/screen
    /// tracks are completed with `withDimensions`; the full strict check is
    /// `validate`, also enforced by `Writer.declareTrack` and encoding.
    pub fn init(id: u16, kind: TrackKind, codec_name: []const u8, clock_rate: u32) Error!Track {
        if (id == 0 or !validCodec(codec_name)) return error.InvalidTrack;
        if (kind != .caption and clock_rate == 0) return error.InvalidTrack;
        var t: Track = .{ .id = id, .kind = kind, .clock_rate = clock_rate, .codec_len = @intCast(codec_name.len) };
        @memcpy(t.codec_buf[0..codec_name.len], codec_name);
        return t;
    }
    pub fn withDimensions(self: Track, width: u32, height: u32) Error!Track {
        var t = self;
        t.width = width;
        t.height = height;
        try t.validate();
        return t;
    }
    pub fn withLanguage(self: Track, language_tag: []const u8) Error!Track {
        if (!validLanguage(language_tag)) return error.InvalidTrack;
        var t = self;
        t.language_len = @intCast(language_tag.len);
        @memcpy(t.language_buf[0..language_tag.len], language_tag);
        try t.validate();
        return t;
    }
    pub fn codec(self: *const Track) []const u8 {
        return self.codec_buf[0..self.codec_len];
    }
    pub fn language(self: *const Track) []const u8 {
        return self.language_buf[0..self.language_len];
    }
    pub fn validate(self: *const Track) Error!void {
        if (self.id == 0 or self.codec_len > max_codec_len or self.language_len > max_language_len) return error.InvalidTrack;
        if (!validCodec(self.codec())) return error.InvalidTrack;
        if (!validLanguage(self.language())) return error.InvalidTrack;
        for (self.codec_buf[self.codec_len..]) |b| if (b != 0) return error.InvalidTrack;
        for (self.language_buf[self.language_len..]) |b| if (b != 0) return error.InvalidTrack;
        switch (self.kind) {
            .audio, .caption => {
                if (self.width != 0 or self.height != 0) return error.InvalidTrack;
                if (self.kind == .audio and self.clock_rate == 0) return error.InvalidTrack;
            },
            .video, .screen => {
                if (self.clock_rate == 0) return error.InvalidTrack;
                if (self.width == 0 or self.height == 0) return error.InvalidTrack;
            },
        }
    }
    pub fn eql(self: Track, other: Track) bool {
        return self.id == other.id and self.kind == other.kind and
            self.clock_rate == other.clock_rate and self.width == other.width and
            self.height == other.height and std.mem.eql(u8, self.codec(), other.codec()) and
            std.mem.eql(u8, self.language(), other.language());
    }
};

/// One transport-neutral encoded packet. `pts_us` is recording-relative,
/// monotonic nondecreasing per track, and must be >= 0. Caption payloads are
/// opaque bytes to this module (callers choose UTF-8/WebVTT-like content).
pub const Packet = struct {
    track_id: u16,
    pts_us: i64,
    duration_us: u32 = 0,
    keyframe: bool = false,
    end_of_stream: bool = false,
    discontinuity: bool = false,
    payload: []const u8,
};

pub const RecordType = enum(u8) { track_decl = 1, packet = 2, gap = 3, segment_end = 4 };

pub const GapReason = enum(u8) {
    queue_full = 1,
    awaiting_keyframe = 2,
    source_discontinuity = 3,
    quota = 4,
    other = 255,
};

/// Hard caps. Zero means "unset" only where documented; `validate` fills no
/// defaults, so an integrating caller sets every bound explicitly.
pub const Config = struct {
    /// Per-segment on-disk byte cap, header and end frame included.
    max_segment_bytes: u64,
    /// Whole-recording byte quota across all rotated segments.
    max_total_bytes: u64,
    /// Whole-recording duration cap in µs, measured from the first admitted
    /// packet pts to `pts + duration` of each candidate packet. 0 = no cap.
    max_duration_us: i64 = 0,
    max_packet_bytes: u32 = 1024 * 1024,
    max_tracks: usize = 8,
    /// Drop (not error) video/screen packets until a keyframe is seen.
    require_keyframe_first: bool = true,
    /// Optional HMAC-SHA-256 chain key. Without it the chain is plain SHA-256.
    mac_key: ?[32]u8 = null,

    pub fn validate(self: Config) Error!void {
        const minimum = header_len + endFrameLen();
        if (self.max_segment_bytes < minimum) return error.InvalidConfig;
        if (self.max_total_bytes < self.max_segment_bytes) return error.InvalidConfig;
        if (self.max_duration_us < 0) return error.InvalidConfig;
        if (self.max_packet_bytes == 0 or self.max_packet_bytes > max_packet_bytes_hard) return error.InvalidConfig;
        if (self.max_tracks == 0 or self.max_tracks > max_tracks_hard) return error.InvalidConfig;
        // One largest packet plus header and the reserved end frame must fit.
        if (self.max_segment_bytes < header_len + endFrameLen() + frameLen(self.max_packet_bytes)) {
            // Small segments are still legal for tests/rotation cadence: the
            // per-packet check then refuses oversized packets with
            // SegmentFull. Only reject configs that cannot hold any packet.
            if (self.max_segment_bytes < header_len + endFrameLen() + frameLen(1)) return error.InvalidConfig;
        }
    }
};

pub fn frameLen(payload_len: usize) usize {
    return length_len + frame_fixed_len + payload_len + frame_trailer_len;
}
pub const segment_end_payload_len: usize = 32;
pub fn endFrameLen() usize {
    return frameLen(segment_end_payload_len);
}
pub const gap_payload_len: usize = 16;

/// Per-track keyframe gating. Audio/caption always pass. Video/screen pass
/// only at/after a keyframe until `noteDiscontinuity`/`resetTrack` re-arms the
/// gate. Pure value type: reusable standalone by a pump that wants the same
/// drop decision before queueing.
pub const KeyframeGate = struct {
    pub const Decision = enum { accept, drop_awaiting_keyframe };
    const Slot = struct { track_id: u16 = 0, kind: TrackKind = .audio, open: bool = false };
    enabled: bool = true,
    slots: [max_tracks_hard]Slot = @splat(.{}),
    count: usize = 0,
    dropped: u64 = 0,

    pub fn register(self: *KeyframeGate, track: Track) Error!void {
        if (self.find(track.id) != null) return error.DuplicateTrack;
        if (self.count >= max_tracks_hard) return error.TooManyTracks;
        self.slots[self.count] = .{ .track_id = track.id, .kind = track.kind, .open = !track.kind.needsKeyframe() };
        self.count += 1;
    }
    fn find(self: *KeyframeGate, track_id: u16) ?*Slot {
        for (self.slots[0..self.count]) |*s| if (s.track_id == track_id) return s;
        return null;
    }
    /// Decide without mutating. A keyframe on a gated track is acceptable.
    pub fn peek(self: *const KeyframeGate, track_id: u16, keyframe: bool, discontinuity: bool) Decision {
        if (!self.enabled) return .accept;
        for (self.slots[0..self.count]) |s| {
            if (s.track_id != track_id) continue;
            if (!s.kind.needsKeyframe()) return .accept;
            if (keyframe) return .accept;
            if (discontinuity) return .drop_awaiting_keyframe;
            return if (s.open) .accept else .drop_awaiting_keyframe;
        }
        return .drop_awaiting_keyframe;
    }
    /// Decide and record the outcome (accepted keyframes open the gate; a
    /// discontinuity on a non-keyframe closes it again).
    pub fn observe(self: *KeyframeGate, track_id: u16, keyframe: bool, discontinuity: bool) Decision {
        const decision = self.peek(track_id, keyframe, discontinuity);
        if (self.find(track_id)) |s| {
            if (s.kind.needsKeyframe()) {
                if (keyframe) s.open = true else if (discontinuity) s.open = false;
            }
        }
        if (decision == .drop_awaiting_keyframe) self.dropped += 1;
        return decision;
    }
    pub fn noteDiscontinuity(self: *KeyframeGate, track_id: u16) void {
        if (self.find(track_id)) |s| if (s.kind.needsKeyframe()) {
            s.open = false;
        };
    }
    pub fn resetTrack(self: *KeyframeGate, track_id: u16) void {
        self.noteDiscontinuity(track_id);
    }
    pub fn resetAll(self: *KeyframeGate) void {
        for (self.slots[0..self.count]) |*s| s.open = !s.kind.needsKeyframe();
    }
    pub fn isOpen(self: *const KeyframeGate, track_id: u16) bool {
        for (self.slots[0..self.count]) |s| if (s.track_id == track_id) return s.open;
        return false;
    }
};

pub const Header = struct {
    recording_id: RecordingId,
    segment_index: u32,
    created_unix_ms: i64,
    flags: u32,

    pub fn macChain(self: Header) bool {
        return self.flags & flag_mac_chain != 0;
    }
};

/// Layout: magic[8] | version u16 | header_len u16 | flags u32 |
/// recording_id[16] | segment_index u32 | created_unix_ms i64 | reserved[4]=0.
pub fn encodeHeader(header: Header) [header_len]u8 {
    var out: [header_len]u8 = @splat(0);
    @memcpy(out[0..8], magic);
    std.mem.writeInt(u16, out[8..10], format_version, .little);
    std.mem.writeInt(u16, out[10..12], header_len, .little);
    std.mem.writeInt(u32, out[12..16], header.flags, .little);
    @memcpy(out[16..32], &header.recording_id.bytes);
    std.mem.writeInt(u32, out[32..36], header.segment_index, .little);
    std.mem.writeInt(i64, out[36..44], header.created_unix_ms, .little);
    return out;
}

pub fn parseHeader(bytes: []const u8) Error!Header {
    if (bytes.len < header_len) return error.InvalidHeader;
    if (!std.mem.eql(u8, bytes[0..8], magic)) return error.InvalidHeader;
    if (std.mem.readInt(u16, bytes[8..10], .little) != format_version) return error.UnsupportedVersion;
    if (std.mem.readInt(u16, bytes[10..12], .little) != header_len) return error.InvalidHeader;
    const flags = std.mem.readInt(u32, bytes[12..16], .little);
    if (flags & ~flag_mac_chain != 0) return error.InvalidHeader;
    var id_bytes: [recording_id_len]u8 = undefined;
    @memcpy(&id_bytes, bytes[16..32]);
    const id = RecordingId.fromBytes(id_bytes) catch return error.InvalidHeader;
    if (!std.mem.eql(u8, bytes[44..48], &.{ 0, 0, 0, 0 })) return error.InvalidHeader;
    return .{
        .recording_id = id,
        .segment_index = std.mem.readInt(u32, bytes[32..36], .little),
        .created_unix_ms = std.mem.readInt(i64, bytes[36..44], .little),
        .flags = flags,
    };
}

fn chainGenesis(header_bytes: *const [header_len]u8) [32]u8 {
    var h = Sha256.init(.{});
    h.update("ONYXREC1-chain-v1\x00");
    h.update(header_bytes);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

fn chainNext(prev: *const [32]u8, mac_key: ?*const [32]u8, covered: []const u8) [32]u8 {
    // `covered` is seq..payload followed by the crc32c field bytes.
    var out: [32]u8 = undefined;
    if (mac_key) |key| {
        var mac = HmacSha256.init(key);
        mac.update(prev);
        mac.update(covered);
        mac.final(&out);
    } else {
        var h = Sha256.init(.{});
        h.update(prev);
        h.update(covered);
        h.final(&out);
    }
    return out;
}

/// Encode one frame into a fresh allocation. Used by the writer; also the
/// canonical reference for tests/tools that build journals in memory.
pub fn encodeFrameAlloc(
    allocator: std.mem.Allocator,
    seq: u64,
    record_type: RecordType,
    track_id: u16,
    flags: u8,
    pts_us: i64,
    duration_us: u32,
    payload: []const u8,
    prev_chain: *const [32]u8,
    mac_key: ?*const [32]u8,
) !struct { bytes: []u8, chain: [32]u8 } {
    if (payload.len > std.math.maxInt(u32)) return error.PacketTooLarge;
    const total = frameLen(payload.len);
    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);
    std.mem.writeInt(u32, buf[0..4], @intCast(total - length_len), .little);
    var p: usize = length_len;
    std.mem.writeInt(u64, buf[p..][0..8], seq, .little);
    p += 8;
    buf[p] = @backingInt(record_type);
    p += 1;
    std.mem.writeInt(u16, buf[p..][0..2], track_id, .little);
    p += 2;
    buf[p] = flags;
    p += 1;
    std.mem.writeInt(i64, buf[p..][0..8], pts_us, .little);
    p += 8;
    std.mem.writeInt(u32, buf[p..][0..4], duration_us, .little);
    p += 4;
    std.mem.writeInt(u32, buf[p..][0..4], @intCast(payload.len), .little);
    p += 4;
    std.debug.assert(p == length_len + frame_fixed_len);
    @memcpy(buf[p..][0..payload.len], payload);
    p += payload.len;
    const crc = crc32c_mod.crc32c(buf[length_len..p]);
    std.mem.writeInt(u32, buf[p..][0..4], crc, .little);
    p += 4;
    const chain = chainNext(prev_chain, mac_key, buf[length_len..p]);
    @memcpy(buf[p..][0..32], &chain);
    return .{ .bytes = buf, .chain = chain };
}

/// Track-declaration payload: kind u8, codec_len u8, language_len u8,
/// reserved u8=0, clock_rate u32, width u32, height u32, codec, language.
pub const track_decl_fixed_len: usize = 16;
pub fn encodeTrackDecl(allocator: std.mem.Allocator, track: Track) ![]u8 {
    try track.validate();
    const buf = try allocator.alloc(u8, track_decl_fixed_len + track.codec_len + track.language_len);
    errdefer allocator.free(buf);
    buf[0] = @backingInt(track.kind);
    buf[1] = track.codec_len;
    buf[2] = track.language_len;
    buf[3] = 0;
    std.mem.writeInt(u32, buf[4..8], track.clock_rate, .little);
    std.mem.writeInt(u32, buf[8..12], track.width, .little);
    std.mem.writeInt(u32, buf[12..16], track.height, .little);
    @memcpy(buf[16..][0..track.codec_len], track.codec());
    @memcpy(buf[16 + track.codec_len ..][0..track.language_len], track.language());
    return buf;
}

pub fn decodeTrackDecl(track_id: u16, payload: []const u8) Error!Track {
    if (payload.len < track_decl_fixed_len) return error.InvalidTrack;
    const kind = std.enums.fromInt(TrackKind, payload[0]) orelse return error.InvalidTrack;
    if (payload[3] != 0 or payload[1] > max_codec_len or payload[2] > max_language_len) return error.InvalidTrack;
    if (payload.len != track_decl_fixed_len + payload[1] + payload[2]) return error.InvalidTrack;
    var t: Track = .{
        .id = track_id,
        .kind = kind,
        .clock_rate = std.mem.readInt(u32, payload[4..8], .little),
        .width = std.mem.readInt(u32, payload[8..12], .little),
        .height = std.mem.readInt(u32, payload[12..16], .little),
        .codec_len = payload[1],
        .language_len = payload[2],
    };
    @memcpy(t.codec_buf[0..t.codec_len], payload[16..][0..t.codec_len]);
    @memcpy(t.language_buf[0..t.language_len], payload[16 + t.codec_len ..][0..t.language_len]);
    try t.validate();
    return t;
}

pub const SegmentEnd = struct {
    packet_count: u64,
    record_count: u64, // excluding this end frame
    duration_us: i64, // last_pts+duration - first_pts, 0 when no packets
    dropped_gate: u64,
};
fn encodeSegmentEnd(end: SegmentEnd) [segment_end_payload_len]u8 {
    var out: [segment_end_payload_len]u8 = undefined;
    std.mem.writeInt(u64, out[0..8], end.packet_count, .little);
    std.mem.writeInt(u64, out[8..16], end.record_count, .little);
    std.mem.writeInt(i64, out[16..24], end.duration_us, .little);
    std.mem.writeInt(u64, out[24..32], end.dropped_gate, .little);
    return out;
}
pub fn decodeSegmentEnd(payload: []const u8) Error!SegmentEnd {
    if (payload.len != segment_end_payload_len) return error.InvalidPacket;
    return .{
        .packet_count = std.mem.readInt(u64, payload[0..8], .little),
        .record_count = std.mem.readInt(u64, payload[8..16], .little),
        .duration_us = std.mem.readInt(i64, payload[16..24], .little),
        .dropped_gate = std.mem.readInt(u64, payload[24..32], .little),
    };
}
fn encodeGap(reason: GapReason, dropped: u64) [gap_payload_len]u8 {
    var out: [gap_payload_len]u8 = @splat(0);
    out[0] = @backingInt(reason);
    std.mem.writeInt(u64, out[8..16], dropped, .little);
    return out;
}
pub fn decodeGap(payload: []const u8) Error!struct { reason: GapReason, dropped: u64 } {
    if (payload.len != gap_payload_len) return error.InvalidPacket;
    const reason = std.enums.fromInt(GapReason, payload[0]) orelse return error.InvalidPacket;
    if (!std.mem.eql(u8, payload[1..8], &[_]u8{ 0, 0, 0, 0, 0, 0, 0 })) return error.InvalidPacket;
    return .{ .reason = reason, .dropped = std.mem.readInt(u64, payload[8..16], .little) };
}

// ---------------------------------------------------------------------------
// Reader / scanner / torn-tail recovery over bytes
// ---------------------------------------------------------------------------

pub const StopReason = enum {
    end, // clean EOF exactly at a frame boundary
    torn_tail, // bytes end mid-frame / mid-length
    corrupt_crc,
    corrupt_chain,
    bad_length, // length/payload_len inconsistent or over hard cap
    bad_record, // unknown type, bad flags, bad track decl, seq gap, ...
    bad_header,
    missing_mac_key, // header demands MAC chain, scanner has no key
};

pub const RecordView = struct {
    seq: u64,
    record_type: RecordType,
    track_id: u16,
    flags: u8,
    pts_us: i64,
    duration_us: u32,
    payload: []const u8,
    offset: usize, // frame start
    next_offset: usize,

    pub fn keyframe(self: RecordView) bool {
        return self.flags & frame_flag_keyframe != 0;
    }
    pub fn track(self: RecordView) Error!Track {
        if (self.record_type != .track_decl) return error.InvalidPacket;
        return decodeTrackDecl(self.track_id, self.payload);
    }
};

/// Streaming validator over a byte slice. Strict: sequence numbers are dense
/// from 0, flags carry no unknown bits, control records have track_id 0
/// (except track_decl), packets/gaps reference declared tracks, pts is
/// nondecreasing per track, and nothing may follow `segment_end`.
pub const Iterator = struct {
    bytes: []const u8,
    header: ?Header = null,
    next_offset: usize = 0,
    valid_bytes: usize = 0,
    stop_reason: StopReason = .bad_header,
    stopped: bool = false,
    next_seq: u64 = 0,
    chain: [32]u8 = @splat(0),
    mac_key: ?[32]u8 = null,
    ended: bool = false,
    seen_non_decl: bool = false,
    tracks: [max_tracks_hard]Track = undefined,
    track_count: usize = 0,
    last_pts: [max_tracks_hard]i64 = @splat(-1),

    pub fn init(bytes: []const u8, mac_key: ?[32]u8) Iterator {
        var it: Iterator = .{ .bytes = bytes, .mac_key = mac_key };
        const header = parseHeader(bytes) catch {
            it.stopped = true;
            it.stop_reason = .bad_header;
            return it;
        };
        it.header = header;
        it.chain = chainGenesis(bytes[0..header_len]);
        it.next_offset = header_len;
        it.valid_bytes = header_len;
        it.stop_reason = .end;
        if (header.macChain() and mac_key == null) {
            it.stop_reason = .missing_mac_key;
            it.stopped = true;
        }
        return it;
    }
    fn trackIndex(self: *const Iterator, track_id: u16) ?usize {
        for (self.tracks[0..self.track_count], 0..) |t, i| if (t.id == track_id) return i;
        return null;
    }
    fn stop(self: *Iterator, reason: StopReason) ?RecordView {
        self.stop_reason = reason;
        self.stopped = true;
        return null;
    }
    pub fn next(self: *Iterator) ?RecordView {
        if (self.stopped) return null;
        if (self.header == null) return self.stop(.bad_header);
        const off = self.next_offset;
        if (off == self.bytes.len) return self.stop(.end);
        if (self.ended) return self.stop(.bad_record);
        if (self.bytes.len - off < length_len) return self.stop(.torn_tail);
        const body_len = std.mem.readInt(u32, self.bytes[off..][0..4], .little);
        if (body_len < frame_fixed_len + frame_trailer_len) return self.stop(.bad_length);
        if (body_len > frame_fixed_len + max_packet_bytes_hard + frame_trailer_len) return self.stop(.bad_length);
        const frame_total = length_len + @as(usize, body_len);
        if (self.bytes.len - off < frame_total) return self.stop(.torn_tail);
        const body = self.bytes[off + length_len .. off + frame_total];
        const payload_len = std.mem.readInt(u32, body[24..28], .little);
        if (payload_len != body_len - frame_fixed_len - frame_trailer_len) return self.stop(.bad_length);
        const payload = body[frame_fixed_len .. frame_fixed_len + payload_len];
        const crc_at = frame_fixed_len + payload_len;
        if (crc32c_mod.crc32c(body[0..crc_at]) != std.mem.readInt(u32, body[crc_at..][0..4], .little))
            return self.stop(.corrupt_crc);
        const key_ptr: ?*const [32]u8 = if (self.mac_key) |*k| k else null;
        const expected = chainNext(&self.chain, key_ptr, body[0 .. crc_at + 4]);
        if (!std.mem.eql(u8, &expected, body[crc_at + 4 ..][0..32])) return self.stop(.corrupt_chain);
        const seq = std.mem.readInt(u64, body[0..8], .little);
        const rtype = std.enums.fromInt(RecordType, body[8]) orelse return self.stop(.bad_record);
        const track_id = std.mem.readInt(u16, body[9..11], .little);
        const flags = body[11];
        const pts = std.mem.readInt(i64, body[12..20], .little);
        if (seq != self.next_seq) return self.stop(.bad_record);
        if (flags & ~(frame_flag_keyframe | frame_flag_end_of_stream | frame_flag_discontinuity) != 0)
            return self.stop(.bad_record);
        switch (rtype) {
            .track_decl => {
                if (self.seen_non_decl) return self.stop(.bad_record);
                if (flags != 0 or pts != 0 or std.mem.readInt(u32, body[20..24], .little) != 0) return self.stop(.bad_record);
                const t = decodeTrackDecl(track_id, payload) catch return self.stop(.bad_record);
                if (self.trackIndex(track_id) != null) return self.stop(.bad_record);
                if (self.track_count >= max_tracks_hard) return self.stop(.bad_record);
                self.tracks[self.track_count] = t;
                self.track_count += 1;
            },
            .packet, .gap => {
                self.seen_non_decl = true;
                const idx = self.trackIndex(track_id) orelse return self.stop(.bad_record);
                if (pts < 0 or pts < self.last_pts[idx] or pts > std.math.maxInt(i64) - @as(i64, std.mem.readInt(u32, body[20..24], .little))) return self.stop(.bad_record);
                if (rtype == .packet and payload_len == 0) return self.stop(.bad_record);
                if (rtype == .gap) {
                    if (flags != 0) return self.stop(.bad_record);
                    _ = decodeGap(payload) catch return self.stop(.bad_record);
                }
                self.last_pts[idx] = pts;
            },
            .segment_end => {
                self.seen_non_decl = true;
                if (track_id != 0 or flags != 0 or pts != 0 or std.mem.readInt(u32, body[20..24], .little) != 0) return self.stop(.bad_record);
                _ = decodeSegmentEnd(payload) catch return self.stop(.bad_record);
                self.ended = true;
            },
        }
        self.chain = expected;
        self.next_seq += 1;
        self.next_offset = off + frame_total;
        self.valid_bytes = self.next_offset;
        return .{
            .seq = seq,
            .record_type = rtype,
            .track_id = track_id,
            .flags = flags,
            .pts_us = pts,
            .duration_us = std.mem.readInt(u32, body[20..24], .little),
            .payload = payload,
            .offset = off,
            .next_offset = off + frame_total,
        };
    }
};

pub const ScanResult = struct {
    header: ?Header = null,
    valid_bytes: usize = 0,
    stop_reason: StopReason = .bad_header,
    record_count: u64 = 0,
    packet_count: u64 = 0,
    gap_count: u64 = 0,
    track_count: usize = 0,
    finalized: bool = false, // a valid segment_end frame was seen
    segment_end: ?SegmentEnd = null,
    first_pts_us: ?i64 = null,
    last_end_us: ?i64 = null, // max(pts+duration) over packets
    chain_head: [32]u8 = @splat(0),
    /// SHA-256 of the valid prefix `bytes[0..valid_bytes]`.
    sha256: [32]u8 = @splat(0),

    pub fn durationUs(self: ScanResult) i64 {
        if (self.first_pts_us == null or self.last_end_us == null) return 0;
        return self.last_end_us.? - self.first_pts_us.?;
    }
    pub fn sha256Hex(self: *const ScanResult) [64]u8 {
        return std.fmt.bytesToHex(self.sha256, .lower);
    }
    pub fn chainHex(self: *const ScanResult) [64]u8 {
        return std.fmt.bytesToHex(self.chain_head, .lower);
    }
};

/// Validate a whole journal image without allocating. `valid_bytes` is the
/// torn-tail recovery cut point: bytes after it must be discarded.
pub fn scan(bytes: []const u8, mac_key: ?[32]u8) ScanResult {
    var it = Iterator.init(bytes, mac_key);
    var result: ScanResult = .{ .header = it.header, .chain_head = it.chain };
    while (it.next()) |rec| {
        result.record_count += 1;
        switch (rec.record_type) {
            .packet => {
                result.packet_count += 1;
                if (result.first_pts_us == null) result.first_pts_us = rec.pts_us;
                const end_us = rec.pts_us + @as(i64, rec.duration_us);
                if (result.last_end_us == null or end_us > result.last_end_us.?) result.last_end_us = end_us;
            },
            .gap => result.gap_count += 1,
            .track_decl => result.track_count += 1,
            .segment_end => {
                result.finalized = true;
                result.segment_end = decodeSegmentEnd(rec.payload) catch null;
            },
        }
    }
    result.valid_bytes = it.valid_bytes;
    result.stop_reason = it.stop_reason;
    result.chain_head = it.chain;
    Sha256.hash(bytes[0..result.valid_bytes], &result.sha256, .{});
    return result;
}

/// Segment manifest data — everything an index/catalogue needs without
/// reopening the journal. Produced by `Writer.finalize`/`rotate`; `scan`
/// output can rebuild the cryptographic fields for verification.
pub const Manifest = struct {
    recording_id: RecordingId,
    segment_index: u32,
    created_unix_ms: i64,
    /// Final file basename (random-id derived; see `finalName`).
    file_name_buf: [96]u8 = @splat(0),
    file_name_len: u8 = 0,
    bytes: u64,
    sha256: [32]u8,
    chain_head: [32]u8,
    record_count: u64, // including the segment_end frame
    packet_count: u64,
    first_pts_us: ?i64,
    duration_us: i64,
    tracks: [max_tracks_hard]Track = undefined,
    track_count: usize = 0,
    mac_chain: bool = false,

    pub fn fileName(self: *const Manifest) []const u8 {
        return self.file_name_buf[0..self.file_name_len];
    }
    pub fn recordingHex(self: *const Manifest) [recording_id_hex_len]u8 {
        return self.recording_id.hex();
    }
    pub fn sha256Hex(self: *const Manifest) [64]u8 {
        return std.fmt.bytesToHex(self.sha256, .lower);
    }
    pub fn chainHex(self: *const Manifest) [64]u8 {
        return std.fmt.bytesToHex(self.chain_head, .lower);
    }
    /// Deterministic single-line JSON. Caller owns the allocation. Track
    /// codec/language are restricted charsets (see `Track.validate`), so no
    /// JSON escaping beyond the fixed field names is required.
    pub fn encodeAlloc(self: *const Manifest, allocator: std.mem.Allocator) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        const rec_hex = self.recordingHex();
        const sha_hex = self.sha256Hex();
        const chain_hex = self.chainHex();
        try out.print(allocator, "{{\"format\":\"ONYXREC1\",\"version\":{d},\"recording_id\":\"{s}\",\"segment\":{d},\"created_unix_ms\":{d},\"file\":\"{s}\",\"bytes\":{d},\"sha256\":\"{s}\",\"chain\":\"{s}\",\"mac_chain\":{},\"records\":{d},\"packets\":{d},\"first_pts_us\":", .{
            format_version, &rec_hex, self.segment_index, self.created_unix_ms, self.fileName(), self.bytes, &sha_hex, &chain_hex, self.mac_chain, self.record_count, self.packet_count,
        });
        if (self.first_pts_us) |v| try out.print(allocator, "{d}", .{v}) else try out.appendSlice(allocator, "null");
        try out.print(allocator, ",\"duration_us\":{d},\"tracks\":[", .{self.duration_us});
        for (self.tracks[0..self.track_count], 0..) |t, i| {
            if (i > 0) try out.append(allocator, ',');
            try out.print(allocator, "{{\"id\":{d},\"kind\":\"{s}\",\"codec\":\"{s}\",\"clock_rate\":{d},\"width\":{d},\"height\":{d},\"language\":\"{s}\"}}", .{
                t.id, t.kind.name(), t.codec(), t.clock_rate, t.width, t.height, t.language(),
            });
        }
        try out.appendSlice(allocator, "]}\n");
        return out.toOwnedSlice(allocator);
    }
};

/// True when `bytes` is exactly the finalized segment the manifest describes.
pub fn verifyManifest(bytes: []const u8, manifest: *const Manifest, mac_key: ?[32]u8) bool {
    if (bytes.len != manifest.bytes) return false;
    const s = scan(bytes, mac_key);
    if (!s.finalized or s.stop_reason != .end) return false;
    const header = s.header orelse return false;
    return header.recording_id.eql(manifest.recording_id) and
        header.segment_index == manifest.segment_index and
        header.macChain() == manifest.mac_chain and
        std.mem.eql(u8, &s.sha256, &manifest.sha256) and
        std.mem.eql(u8, &s.chain_head, &manifest.chain_head) and
        s.record_count == manifest.record_count and s.packet_count == manifest.packet_count;
}

// ---------------------------------------------------------------------------
// Bounded SPSC queue (pump producer -> recorder consumer)
// ---------------------------------------------------------------------------

pub const PushOutcome = enum { queued, full, byte_budget, too_large, invalid, closed, out_of_memory };

pub const QueuedPacket = struct {
    track_id: u16,
    pts_us: i64,
    duration_us: u32 = 0,
    keyframe: bool = false,
    end_of_stream: bool = false,
    discontinuity: bool = false,
    track: ?Track = null, // inline descriptor; never borrows producer strings
    payload: []u8, // owned by the queue, then by whoever pops it

    pub fn packet(self: *const QueuedPacket) Packet {
        return .{
            .track_id = self.track_id,
            .pts_us = self.pts_us,
            .duration_us = self.duration_us,
            .keyframe = self.keyframe,
            .end_of_stream = self.end_of_stream,
            .discontinuity = self.discontinuity,
            .payload = self.payload,
        };
    }
    pub fn deinit(self: *QueuedPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

/// Fixed-capacity single-producer/single-consumer ring. `tryPush` never
/// blocks: on `full`/`byte_budget`/`too_large`/`closed`/`out_of_memory` the
/// packet is simply not queued (the caller counts a drop / writes a gap
/// record later). Exactly one producer thread may call the push side and
/// exactly one consumer the pop/peek side; stats are atomic snapshots.
pub const Queue = struct {
    allocator: std.mem.Allocator,
    slots: []?QueuedPacket,
    capacity_bytes: usize,
    max_packet_bytes: u32,
    head: std.atomic.Value(usize) = .init(0), // consumer-owned index
    tail: std.atomic.Value(usize) = .init(0), // producer-owned index
    bytes: std.atomic.Value(usize) = .init(0),
    closed_flag: std.atomic.Value(bool) = .init(false),
    pushed: std.atomic.Value(u64) = .init(0),
    dropped_full: std.atomic.Value(u64) = .init(0),
    dropped_other: std.atomic.Value(u64) = .init(0),

    pub fn init(allocator: std.mem.Allocator, capacity_items: usize, capacity_bytes: usize, max_packet_bytes: u32) !Queue {
        if (capacity_items == 0 or capacity_bytes == 0 or max_packet_bytes == 0 or max_packet_bytes > max_packet_bytes_hard)
            return error.InvalidConfig;
        // One slot stays empty so head == tail unambiguously means empty.
        const slots = try allocator.alloc(?QueuedPacket, capacity_items + 1);
        @memset(slots, null);
        return .{ .allocator = allocator, .slots = slots, .capacity_bytes = capacity_bytes, .max_packet_bytes = max_packet_bytes };
    }
    pub fn deinit(self: *Queue) void {
        for (self.slots) |*slot| if (slot.*) |*qp| qp.deinit(self.allocator);
        self.allocator.free(self.slots);
        self.* = undefined;
    }
    pub fn close(self: *Queue) void {
        self.closed_flag.store(true, .release);
    }
    pub fn isClosed(self: *const Queue) bool {
        return self.closed_flag.load(.acquire);
    }
    pub fn len(self: *const Queue) usize {
        const tail = self.tail.load(.acquire);
        const head = self.head.load(.acquire);
        return (tail + self.slots.len - head) % self.slots.len;
    }
    pub fn isEmpty(self: *const Queue) bool {
        return self.len() == 0;
    }
    pub fn queuedBytes(self: *const Queue) usize {
        return self.bytes.load(.acquire);
    }

    /// Copying push for borrowed pump payloads. Allocates one payload copy;
    /// allocation failure is reported, never panics, never blocks.
    pub fn tryPush(self: *Queue, pkt: Packet) PushOutcome {
        return self.pushPacket(null, pkt);
    }

    /// Stage a track declaration with a copied packet. Only the consumer
    /// touches the journal; metadata remains valid after producer return.
    pub fn tryPushTrack(self: *Queue, track: Track, pkt: Packet) PushOutcome {
        track.validate() catch {
            _ = self.dropped_other.fetchAdd(1, .monotonic);
            return .invalid;
        };
        if (track.id != pkt.track_id) {
            _ = self.dropped_other.fetchAdd(1, .monotonic);
            return .invalid;
        }
        return self.pushPacket(track, pkt);
    }

    fn pushPacket(self: *Queue, track: ?Track, pkt: Packet) PushOutcome {
        if (pkt.track_id == 0 or pkt.pts_us < 0 or pkt.payload.len == 0) {
            _ = self.dropped_other.fetchAdd(1, .monotonic);
            return .invalid;
        }
        if (pkt.payload.len > self.max_packet_bytes) {
            _ = self.dropped_other.fetchAdd(1, .monotonic);
            return .too_large;
        }
        const copy = self.allocator.dupe(u8, pkt.payload) catch {
            _ = self.dropped_other.fetchAdd(1, .monotonic);
            return .out_of_memory;
        };
        const outcome = self.tryPushOwned(.{
            .track_id = pkt.track_id,
            .pts_us = pkt.pts_us,
            .duration_us = pkt.duration_us,
            .keyframe = pkt.keyframe,
            .end_of_stream = pkt.end_of_stream,
            .discontinuity = pkt.discontinuity,
            .track = track,
        }, copy);
        if (outcome != .queued) self.allocator.free(copy);
        return outcome;
    }

    /// Zero-copy push. Ownership of `owned_payload` transfers to the queue
    /// only when the result is `.queued`; otherwise the caller still owns it.
    pub fn tryPushOwned(self: *Queue, meta: struct {
        track_id: u16,
        pts_us: i64,
        duration_us: u32 = 0,
        keyframe: bool = false,
        end_of_stream: bool = false,
        discontinuity: bool = false,
        track: ?Track = null,
    }, owned_payload: []u8) PushOutcome {
        if (meta.track) |track| {
            track.validate() catch {
                _ = self.dropped_other.fetchAdd(1, .monotonic);
                return .invalid;
            };
            if (track.id != meta.track_id) {
                _ = self.dropped_other.fetchAdd(1, .monotonic);
                return .invalid;
            }
        }
        if (meta.track_id == 0 or meta.pts_us < 0 or meta.pts_us > std.math.maxInt(i64) - @as(i64, meta.duration_us) or owned_payload.len == 0) {
            _ = self.dropped_other.fetchAdd(1, .monotonic);
            return .invalid;
        }
        if (self.isClosed()) {
            _ = self.dropped_other.fetchAdd(1, .monotonic);
            return .closed;
        }
        if (owned_payload.len > self.max_packet_bytes) {
            _ = self.dropped_other.fetchAdd(1, .monotonic);
            return .too_large;
        }
        if (self.bytes.load(.acquire) + owned_payload.len > self.capacity_bytes) {
            _ = self.dropped_full.fetchAdd(1, .monotonic);
            return .byte_budget;
        }
        const tail = self.tail.load(.monotonic);
        const next = (tail + 1) % self.slots.len;
        if (next == self.head.load(.acquire)) {
            _ = self.dropped_full.fetchAdd(1, .monotonic);
            return .full;
        }
        self.slots[tail] = .{
            .track_id = meta.track_id,
            .pts_us = meta.pts_us,
            .duration_us = meta.duration_us,
            .keyframe = meta.keyframe,
            .end_of_stream = meta.end_of_stream,
            .discontinuity = meta.discontinuity,
            .track = meta.track,
            .payload = owned_payload,
        };
        _ = self.bytes.fetchAdd(owned_payload.len, .monotonic);
        _ = self.pushed.fetchAdd(1, .monotonic);
        self.tail.store(next, .release);
        return .queued;
    }

    /// Consumer-only look at the oldest item without removing it. The pointer
    /// stays valid until `pop`/`consume` is called by the same consumer.
    pub fn peek(self: *Queue) ?*QueuedPacket {
        const head = self.head.load(.monotonic);
        if (head == self.tail.load(.acquire)) return null;
        return &self.slots[head].?;
    }
    pub fn pop(self: *Queue) ?QueuedPacket {
        const head = self.head.load(.monotonic);
        if (head == self.tail.load(.acquire)) return null;
        const item = self.slots[head].?;
        self.slots[head] = null;
        _ = self.bytes.fetchSub(item.payload.len, .monotonic);
        self.head.store((head + 1) % self.slots.len, .release);
        return item;
    }
};

// ---------------------------------------------------------------------------
// Store: private directory, random-id file names, segment writer
// ---------------------------------------------------------------------------

const file_permissions: std.Io.File.Permissions = if (std.posix.mode_t == u0 or builtin.os.tag == .windows)
    .default_file
else
    .fromMode(0o600);
const dir_permissions: std.Io.File.Permissions = if (std.posix.mode_t == u0 or builtin.os.tag == .windows)
    .default_dir
else
    .fromMode(0o700);

/// In-progress segment basename: `rec-<32hex>-s<NNNNNN>.part`.
pub fn partName(buf: []u8, id: RecordingId, segment_index: u32) Error![]u8 {
    const hex = id.hex();
    return std.fmt.bufPrint(buf, "rec-{s}-s{d:0>6}.part", .{ &hex, segment_index }) catch return error.InvalidName;
}
/// Finalized segment basename: `rec-<32hex>-s<NNNNNN>.onyxrec`.
pub fn finalName(buf: []u8, id: RecordingId, segment_index: u32) Error![]u8 {
    const hex = id.hex();
    return std.fmt.bufPrint(buf, "rec-{s}-s{d:0>6}.onyxrec", .{ &hex, segment_index }) catch return error.InvalidName;
}
/// Manifest sidecar basename for one segment.
pub fn manifestName(buf: []u8, id: RecordingId, segment_index: u32) Error![]u8 {
    const hex = id.hex();
    return std.fmt.bufPrint(buf, "rec-{s}-s{d:0>6}.manifest.json", .{ &hex, segment_index }) catch return error.InvalidName;
}

/// True only for names this module itself can mint. Recovery/catalogue code
/// should ignore anything else in the directory.
pub fn isOwnedSegmentName(name: []const u8) bool {
    // rec- (4) + 32 hex + -s (2) + 6 digits + suffix
    if (name.len != 4 + 32 + 2 + 6 + ".onyxrec".len and name.len != 4 + 32 + 2 + 6 + ".part".len) return false;
    if (!std.mem.startsWith(u8, name, "rec-")) return false;
    for (name[4..36]) |b| if (!((b >= '0' and b <= '9') or (b >= 'a' and b <= 'f'))) return false;
    if (!std.mem.eql(u8, name[36..38], "-s")) return false;
    for (name[38..44]) |b| if (b < '0' or b > '9') return false;
    const suffix = name[44..];
    return std.mem.eql(u8, suffix, ".onyxrec") or std.mem.eql(u8, suffix, ".part");
}

fn requirePrivateDir(io: std.Io, dir: std.Io.Dir) !void {
    if (comptime builtin.os.tag == .windows or std.posix.mode_t == u0) return;
    var as_file = try dir.openFile(io, ".", .{ .mode = .read_only, .allow_directory = true });
    defer as_file.close(io);
    const stat = try as_file.stat(io);
    if (stat.kind != .directory) return error.UnprotectedDirectory;
    if (stat.permissions.toMode() & 0o7777 != 0o700) return error.UnprotectedDirectory;
}

/// Create (0700) or open-and-verify (exactly 0700 on POSIX) a recordings
/// directory under `parent`. A pre-existing broader directory is refused,
/// never silently chmodded. Caller closes the returned handle.
pub fn ensurePrivateDir(parent: std.Io.Dir, io: std.Io, name: []const u8) !std.Io.Dir {
    if (name.len == 0 or std.mem.indexOfScalar(u8, name, '/') != null or
        std.mem.indexOfScalar(u8, name, '\\') != null or std.mem.eql(u8, name, ".") or
        std.mem.eql(u8, name, "..")) return error.InvalidName;
    parent.createDir(io, name, dir_permissions) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const dir = try parent.openDir(io, name, .{});
    errdefer dir.close(io);
    try requirePrivateDir(io, dir);
    return dir;
}

fn syncDir(io: std.Io, dir: std.Io.Dir) !void {
    if (comptime builtin.os.tag == .windows) return;
    var as_file = try dir.openFile(io, ".", .{ .mode = .read_only, .allow_directory = true });
    defer as_file.close(io);
    try as_file.sync(io);
}

pub const WriteOutcome = enum { written, dropped_awaiting_keyframe };
pub const WriterStats = struct {
    packets_written: u64 = 0,
    packets_dropped_gate: u64 = 0,
    records_written: u64 = 0, // current segment, excluding a future end frame
    gaps_written: u64 = 0,
    segment_bytes: u64 = 0,
    finalized_bytes: u64 = 0, // sealed segments of this recording
    segments_finalized: u32 = 0,
};

pub const WriterOptions = struct {
    config: Config,
    /// Null mints a fresh random id from `io`.
    recording_id: ?RecordingId = null,
    segment_index: u32 = 0,
    created_unix_ms: i64 = 0,
};

/// Append-only segment writer. Not thread-safe by design: it is the single
/// consumer behind `Queue`. Journal write/fsync or rename errors poison the
/// writer (`WriterFailed` thereafter); recovery then owns the `.part` file.
/// After rename, finalization retains the sealed manifest and can retry the
/// directory sync without touching journal bytes or accounting again.
pub const Writer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    config: Config,
    recording_id: RecordingId,
    segment_index: u32,
    created_unix_ms: i64,
    file: ?std.Io.File = null,
    part_name_buf: [96]u8 = @splat(0),
    part_name_len: usize = 0,
    seq: u64 = 0,
    chain: [32]u8 = @splat(0),
    sha: Sha256 = Sha256.init(.{}),
    bytes_written: u64 = 0,
    tracks: [max_tracks_hard]Track = undefined,
    track_count: usize = 0,
    last_pts: [max_tracks_hard]i64 = @splat(-1),
    gate: KeyframeGate = .{},
    first_pts_recording: ?i64 = null, // duration-cap baseline across rotation
    first_pts_segment: ?i64 = null,
    last_end_segment: ?i64 = null,
    stats: WriterStats = .{},
    segment_packets_base: u64 = 0, // stats.packets_written at last seal
    segment_dropped_base: u64 = 0,
    closed: bool = false,
    failed: bool = false,
    pending_manifest: ?Manifest = null, // retry sidecar before consuming more packets
    final_manifest: ?Manifest = null, // current renamed segment, retained across directory-sync failure

    pub fn create(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, options: WriterOptions) !Writer {
        try options.config.validate();
        const id = options.recording_id orelse RecordingId.random(io);
        if (id.isZero()) return error.InvalidRecordingId;
        var w: Writer = .{
            .allocator = allocator,
            .io = io,
            .dir = dir,
            .config = options.config,
            .recording_id = id,
            .segment_index = options.segment_index,
            .created_unix_ms = options.created_unix_ms,
            .gate = .{ .enabled = options.config.require_keyframe_first },
        };
        errdefer w.abort();
        try w.openSegment();
        return w;
    }

    fn partNameSlice(self: *const Writer) []const u8 {
        return self.part_name_buf[0..self.part_name_len];
    }
    fn closeFileOnly(self: *Writer) void {
        if (self.file) |f| f.close(self.io);
        self.file = null;
    }
    /// Close the handle, leaving any `.part` file for `recoverFile`.
    pub fn deinit(self: *Writer) void {
        self.closeFileOnly();
        self.closed = true;
        self.* = undefined;
    }
    /// Close and delete the in-progress `.part` (explicit abandonment).
    pub fn abort(self: *Writer) void {
        const name = self.partNameSlice();
        var buf: [96]u8 = undefined;
        @memcpy(buf[0..name.len], name);
        const owned = buf[0..name.len];
        self.closeFileOnly();
        self.dir.deleteFile(self.io, owned) catch {};
        self.closed = true;
    }

    fn openSegment(self: *Writer) !void {
        var name_buf: [96]u8 = undefined;
        const name = try partName(&name_buf, self.recording_id, self.segment_index);
        @memcpy(self.part_name_buf[0..name.len], name);
        self.part_name_len = name.len;
        const file = try self.dir.createFile(self.io, self.partNameSlice(), .{
            .read = true,
            .truncate = false,
            .exclusive = true,
            .permissions = file_permissions,
        });
        self.file = file;
        errdefer self.closeFileOnly();
        const header: Header = .{
            .recording_id = self.recording_id,
            .segment_index = self.segment_index,
            .created_unix_ms = self.created_unix_ms,
            .flags = if (self.config.mac_key != null) flag_mac_chain else 0,
        };
        const header_bytes = encodeHeader(header);
        try file.writePositionalAll(self.io, &header_bytes, 0);
        self.chain = chainGenesis(&header_bytes);
        self.sha = Sha256.init(.{});
        self.sha.update(&header_bytes);
        self.bytes_written = header_len;
        self.seq = 0;
        self.first_pts_segment = null;
        self.last_end_segment = null;
        self.stats.records_written = 0;
        self.stats.segment_bytes = header_len;
    }

    fn macKeyPtr(self: *const Writer) ?*const [32]u8 {
        if (self.config.mac_key) |*k| return k;
        return null;
    }
    fn checkOpen(self: *const Writer) Error!void {
        if (self.failed) return error.WriterFailed;
        if (self.closed or self.file == null) return error.WriterClosed;
    }
    /// Caps gate, end-frame reserve included. Pure: no bytes are written.
    fn checkFit(self: *const Writer, payload_len: usize, reserve_end: bool) Error!void {
        const need: u64 = frameLen(payload_len) + @as(usize, if (reserve_end) endFrameLen() else 0);
        if (self.bytes_written + need > self.config.max_segment_bytes) return error.SegmentFull;
        if (self.stats.finalized_bytes + self.bytes_written + need > self.config.max_total_bytes) return error.QuotaExceeded;
    }
    pub fn wouldFit(self: *const Writer, payload_len: usize) bool {
        self.checkFit(payload_len, true) catch return false;
        return true;
    }

    fn appendFrame(self: *Writer, rtype: RecordType, track_id: u16, flags: u8, pts: i64, duration: u32, payload: []const u8) !void {
        const encoded = try encodeFrameAlloc(self.allocator, self.seq, rtype, track_id, flags, pts, duration, payload, &self.chain, self.macKeyPtr());
        defer self.allocator.free(encoded.bytes);
        self.file.?.writePositionalAll(self.io, encoded.bytes, self.bytes_written) catch |err| {
            self.failed = true;
            return err;
        };
        self.chain = encoded.chain;
        self.sha.update(encoded.bytes);
        self.bytes_written += encoded.bytes.len;
        self.seq += 1;
        self.stats.records_written += 1;
        self.stats.segment_bytes = self.bytes_written;
    }

    fn trackIndex(self: *const Writer, track_id: u16) ?usize {
        for (self.tracks[0..self.track_count], 0..) |t, i| if (t.id == track_id) return i;
        return null;
    }

    pub fn declareTrack(self: *Writer, track: Track) !void {
        try self.checkOpen();
        try track.validate();
        if (self.trackIndex(track.id) != null) return error.DuplicateTrack;
        if (self.seq != self.track_count) return error.InvalidTrack; // decls precede all other frames in a segment
        if (self.track_count >= self.config.max_tracks) return error.TooManyTracks;
        const payload = try encodeTrackDecl(self.allocator, track);
        defer self.allocator.free(payload);
        try self.checkFit(payload.len, true);
        try self.appendFrame(.track_decl, track.id, 0, 0, 0, payload);
        self.tracks[self.track_count] = track;
        self.track_count += 1;
        try self.gate.register(track);
    }

    /// Gate/caps/ordering checks run before any write. A gated drop is an
    /// outcome, not an error; every refusal leaves the journal untouched.
    pub fn writePacket(self: *Writer, pkt: Packet) !WriteOutcome {
        try self.checkOpen();
        if (pkt.pts_us < 0 or pkt.pts_us > std.math.maxInt(i64) - @as(i64, pkt.duration_us) or pkt.payload.len == 0) return error.InvalidPacket;
        if (pkt.payload.len > self.config.max_packet_bytes) return error.PacketTooLarge;
        const idx = self.trackIndex(pkt.track_id) orelse return error.UnknownTrack;
        if (pkt.pts_us < self.last_pts[idx]) return error.OutOfOrderPts;
        if (self.gate.peek(pkt.track_id, pkt.keyframe, pkt.discontinuity) == .drop_awaiting_keyframe) {
            _ = self.gate.observe(pkt.track_id, pkt.keyframe, pkt.discontinuity);
            self.stats.packets_dropped_gate += 1;
            return .dropped_awaiting_keyframe;
        }
        if (self.config.max_duration_us > 0) {
            const base = self.first_pts_recording orelse pkt.pts_us;
            const end = pkt.pts_us + @as(i64, pkt.duration_us);
            if (end - base > self.config.max_duration_us) return error.DurationCapExceeded;
        }
        try self.checkFit(pkt.payload.len, true);
        var flags: u8 = 0;
        if (pkt.keyframe) flags |= frame_flag_keyframe;
        if (pkt.end_of_stream) flags |= frame_flag_end_of_stream;
        if (pkt.discontinuity) flags |= frame_flag_discontinuity;
        try self.appendFrame(.packet, pkt.track_id, flags, pkt.pts_us, pkt.duration_us, pkt.payload);
        _ = self.gate.observe(pkt.track_id, pkt.keyframe, pkt.discontinuity);
        self.last_pts[idx] = pkt.pts_us;
        if (self.first_pts_recording == null) self.first_pts_recording = pkt.pts_us;
        if (self.first_pts_segment == null) self.first_pts_segment = pkt.pts_us;
        const end = pkt.pts_us + @as(i64, pkt.duration_us);
        if (self.last_end_segment == null or end > self.last_end_segment.?) self.last_end_segment = end;
        self.stats.packets_written += 1;
        return .written;
    }

    pub fn writeGap(self: *Writer, track_id: u16, pts_us: i64, reason: GapReason, dropped: u64) !void {
        try self.checkOpen();
        if (pts_us < 0) return error.InvalidPacket;
        const idx = self.trackIndex(track_id) orelse return error.UnknownTrack;
        if (pts_us < self.last_pts[idx]) return error.OutOfOrderPts;
        try self.checkFit(gap_payload_len, true);
        try self.appendFrame(.gap, track_id, 0, pts_us, 0, &encodeGap(reason, dropped));
        self.last_pts[idx] = pts_us;
        self.gate.noteDiscontinuity(track_id);
        self.stats.gaps_written += 1;
    }

    fn flushPendingManifest(self: *Writer) !void {
        if (self.pending_manifest) |*manifest| {
            try writeManifestFile(self.allocator, self.io, self.dir, manifest);
            self.pending_manifest = null;
        }
    }

    fn rotateQueued(self: *Writer) !void {
        try self.flushPendingManifest();
        self.pending_manifest = try self.rotate();
        try self.flushPendingManifest();
    }

    fn rotateOrExhaust(self: *Writer, queue: *Queue) !bool {
        self.rotateQueued() catch |err| switch (err) {
            error.SegmentFull, error.QuotaExceeded, error.InvalidName => {
                exhaustQueue(queue);
                return false;
            },
            else => return err,
        };
        return true;
    }

    fn discardHead(queue: *Queue) void {
        var consumed = queue.pop().?;
        consumed.deinit(queue.allocator);
    }

    fn exhaustQueue(queue: *Queue) void {
        queue.close();
        while (!queue.isEmpty()) {
            discardHead(queue);
            _ = queue.dropped_other.fetchAdd(1, .monotonic);
        }
    }

    /// Consumer-only durable drain. Late tracks start a new segment so every
    /// segment retains strict declaration-before-packet framing. Segment caps
    /// rotate automatically; whole-recording caps close and empty the queue,
    /// signalling callers to stop recording. Allocation/sidecar errors retain
    /// the head for retry; invalid packets are discarded without poisoning it.
    pub fn drainQueue(self: *Writer, queue: *Queue, budget: usize) !usize {
        try self.flushPendingManifest();
        try self.checkOpen();
        var written: usize = 0;
        var consumed_count: usize = 0;
        while (consumed_count < budget) {
            const head = queue.peek() orelse break;
            if (head.track) |track| {
                if (self.trackIndex(track.id)) |idx| {
                    if (!self.tracks[idx].eql(track)) {
                        discardHead(queue);
                        _ = queue.dropped_other.fetchAdd(1, .monotonic);
                        consumed_count += 1;
                        continue;
                    }
                } else {
                    if (self.track_count >= self.config.max_tracks) {
                        discardHead(queue);
                        _ = queue.dropped_other.fetchAdd(1, .monotonic);
                        consumed_count += 1;
                        continue;
                    }
                    if (self.seq != self.track_count and !try self.rotateOrExhaust(queue)) break;
                    self.declareTrack(track) catch |err| switch (err) {
                        error.SegmentFull, error.QuotaExceeded => {
                            exhaustQueue(queue);
                            break;
                        },
                        else => return err,
                    };
                }
            }
            const outcome = self.writePacket(head.packet()) catch |err| switch (err) {
                error.SegmentFull => {
                    // A fresh declaration-only segment cannot fit this packet.
                    // Finalize the valid prefix instead of rotating forever.
                    if (self.seq == self.track_count) {
                        exhaustQueue(queue);
                        break;
                    }
                    if (!try self.rotateOrExhaust(queue)) break;
                    continue;
                },
                error.QuotaExceeded, error.DurationCapExceeded => {
                    exhaustQueue(queue);
                    break;
                },
                error.InvalidPacket, error.PacketTooLarge, error.UnknownTrack, error.OutOfOrderPts => {
                    discardHead(queue);
                    _ = queue.dropped_other.fetchAdd(1, .monotonic);
                    consumed_count += 1;
                    continue;
                },
                else => return err,
            };
            discardHead(queue);
            consumed_count += 1;
            if (outcome == .written) written += 1;
        }
        return written;
    }

    fn segmentDuration(self: *const Writer) i64 {
        if (self.first_pts_segment == null or self.last_end_segment == null) return 0;
        return self.last_end_segment.? - self.first_pts_segment.?;
    }

    /// Seal the current segment: end frame, file fsync, close, atomic-ish
    /// rename `.part` -> `.onyxrec`, directory fsync. The writer is closed
    /// afterwards (`rotate` is the way to keep recording). Once renamed,
    /// retries only sync the directory and return the same retained manifest.
    pub fn finalize(self: *Writer) !Manifest {
        try self.flushPendingManifest();
        if (self.final_manifest) |manifest| {
            try syncDir(self.io, self.dir);
            return manifest;
        }
        try self.checkOpen();
        if (self.track_count == 0) return error.InvalidTrack;
        try self.checkFit(segment_end_payload_len, false);
        var final_buf: [96]u8 = undefined;
        const final_name = try finalName(&final_buf, self.recording_id, self.segment_index);
        const end: SegmentEnd = .{
            .packet_count = self.stats.packets_written - self.segment_packets_base,
            .record_count = self.stats.records_written,
            .duration_us = self.segmentDuration(),
            .dropped_gate = self.stats.packets_dropped_gate - self.segment_dropped_base,
        };
        try self.appendFrame(.segment_end, 0, 0, 0, 0, &encodeSegmentEnd(end));
        self.file.?.sync(self.io) catch |err| {
            self.failed = true;
            self.closed = true;
            self.closeFileOnly();
            return err;
        };
        self.closeFileOnly();
        self.closed = true;
        self.dir.rename(self.partNameSlice(), self.dir, final_name, self.io) catch |err| {
            self.failed = true;
            return err;
        };
        // Rename is the sealing boundary. Retain custody before the remaining
        // fallible durability step; never append another end or count twice.
        self.final_manifest = self.buildManifest(final_name);
        try syncDir(self.io, self.dir);
        return self.final_manifest.?;
    }
    fn buildManifest(self: *Writer, final_name: []const u8) Manifest {
        var digest: [32]u8 = undefined;
        var sha_copy = self.sha;
        sha_copy.final(&digest);
        var m: Manifest = .{
            .recording_id = self.recording_id,
            .segment_index = self.segment_index,
            .created_unix_ms = self.created_unix_ms,
            .bytes = self.bytes_written,
            .sha256 = digest,
            .chain_head = self.chain,
            .record_count = self.stats.records_written,
            .packet_count = self.stats.packets_written - self.segment_packets_base,
            .first_pts_us = self.first_pts_segment,
            .duration_us = self.segmentDuration(),
            .track_count = self.track_count,
            .mac_chain = self.config.mac_key != null,
        };
        @memcpy(m.file_name_buf[0..final_name.len], final_name);
        m.file_name_len = @intCast(final_name.len);
        @memcpy(m.tracks[0..self.track_count], self.tracks[0..self.track_count]);
        self.stats.finalized_bytes += self.bytes_written;
        self.stats.segments_finalized += 1;
        self.segment_packets_base = self.stats.packets_written;
        self.segment_dropped_base = self.stats.packets_dropped_gate;
        return m;
    }

    /// Seal the current segment and immediately open the next one with the
    /// same track declarations re-emitted and keyframe gates re-armed, so
    /// every segment independently starts at a keyframe for gated kinds.
    /// Total-bytes quota and the duration baseline carry across rotation.
    pub fn rotate(self: *Writer) !Manifest {
        try self.checkOpen();
        if (self.segment_index == 999999) return error.InvalidName;
        const next_header = encodeHeader(.{
            .recording_id = self.recording_id,
            .segment_index = self.segment_index + 1,
            .created_unix_ms = self.created_unix_ms,
            .flags = if (self.config.mac_key != null) flag_mac_chain else 0,
        });
        var next_chain = chainGenesis(&next_header);
        var frames: [max_tracks_hard]?struct { bytes: []u8, chain: [32]u8 } = @splat(null);
        defer for (&frames) |frame| if (frame) |f| self.allocator.free(f.bytes);
        var next_bytes: u64 = header_len;
        for (self.tracks[0..self.track_count], 0..) |track, i| {
            const payload = try encodeTrackDecl(self.allocator, track);
            defer self.allocator.free(payload);
            const frame = try encodeFrameAlloc(self.allocator, i, .track_decl, track.id, 0, 0, 0, payload, &next_chain, self.macKeyPtr());
            frames[i] = .{ .bytes = frame.bytes, .chain = frame.chain };
            next_bytes += frame.bytes.len;
            next_chain = frame.chain;
        }
        // Preflight both segments' end reserves before sealing the current
        // segment; allocation failures leave its bytes and state untouched.
        if (next_bytes + endFrameLen() > self.config.max_segment_bytes) return error.SegmentFull;
        if (self.stats.finalized_bytes + self.bytes_written + endFrameLen() + next_bytes + endFrameLen() > self.config.max_total_bytes)
            return error.QuotaExceeded;
        const sealed = try self.finalize();
        // Keep custody of the sealed segment even if its successor cannot open.
        self.pending_manifest = sealed;
        self.final_manifest = null;
        self.segment_index += 1;
        self.closed = false;
        self.gate.resetAll();
        errdefer self.failed = true;
        try self.openSegment();
        for (frames[0..self.track_count]) |maybe_frame| {
            const frame = maybe_frame.?;
            try self.file.?.writePositionalAll(self.io, frame.bytes, self.bytes_written);
            self.chain = frame.chain;
            self.sha.update(frame.bytes);
            self.bytes_written += frame.bytes.len;
            self.seq += 1;
            self.stats.records_written += 1;
        }
        self.stats.segment_bytes = self.bytes_written;
        return sealed;
    }
};

/// Persist a manifest sidecar (0600, atomic replace, file + dir fsync).
pub fn writeManifestFile(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, manifest: *const Manifest) !void {
    const encoded = try manifest.encodeAlloc(allocator);
    defer allocator.free(encoded);
    var name_buf: [96]u8 = undefined;
    const name = try manifestName(&name_buf, manifest.recording_id, manifest.segment_index);
    var atomic = try dir.createFileAtomic(io, name, .{ .replace = true, .permissions = file_permissions });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, encoded);
    try atomic.file.sync(io);
    try atomic.replace(io);
    try syncDir(io, dir);
}

pub const RecoveryResult = struct {
    scan: ScanResult,
    original_bytes: u64,
    truncated: bool,
};

/// Read and scan one segment file (bounded by `max_bytes`).
pub fn scanFile(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, name: []const u8, mac_key: ?[32]u8, max_bytes: usize) !ScanResult {
    const bytes = try dir.readFileAlloc(io, name, allocator, .limited(max_bytes));
    defer allocator.free(bytes);
    return scan(bytes, mac_key);
}

/// Torn-tail recovery for a `.part` (or damaged final) file: truncate to the
/// scanner's valid prefix and fsync. Refuses (without touching the file)
/// when even the header is bad, when the MAC key is missing, or when the
/// file is already finalized and clean. Truncation never invents a
/// segment-end frame; a recovered `.part` stays a `.part`.
pub fn recoverFile(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, name: []const u8, mac_key: ?[32]u8, max_bytes: usize) !RecoveryResult {
    if (!isOwnedSegmentName(name)) return error.InvalidName;
    const bytes = try dir.readFileAlloc(io, name, allocator, .limited(max_bytes));
    defer allocator.free(bytes);
    const result = scan(bytes, mac_key);
    var recovery: RecoveryResult = .{ .scan = result, .original_bytes = bytes.len, .truncated = false };
    if (result.header == null or result.stop_reason == .bad_header or result.stop_reason == .missing_mac_key) return recovery;
    if (result.valid_bytes == bytes.len) return recovery;
    var file = try dir.openFile(io, name, .{ .mode = .read_write, .allow_directory = false });
    defer file.close(io);
    // Re-check size under the open handle: a writer that appended since the
    // read must not have its fresh frames cut by a stale scan.
    if ((try file.stat(io)).size != bytes.len) return recovery;
    try file.setLength(io, result.valid_bytes);
    try file.sync(io);
    try syncDir(io, dir);
    recovery.truncated = true;
    return recovery;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testId() RecordingId {
    return .{ .bytes = .{ 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
}
fn testConfig() Config {
    return .{ .max_segment_bytes = 1 << 20, .max_total_bytes = 8 << 20, .max_packet_bytes = 4096, .max_tracks = 8 };
}
fn audioTrack() !Track {
    return Track.init(1, .audio, "cadencevox", 48_000);
}
fn videoTrack() !Track {
    return (try Track.init(2, .video, "cadencevis", 90_000)).withDimensions(1280, 720);
}
fn testWriter(dir: std.Io.Dir, config: Config) !Writer {
    return Writer.create(testing.allocator, testing.io, dir, .{
        .config = config,
        .recording_id = testId(),
        .created_unix_ms = 1_700_000_000_000,
    });
}
fn fileMode(dir: std.Io.Dir, name: []const u8) !std.posix.mode_t {
    const stat = try dir.statFile(testing.io, name, .{});
    return stat.permissions.toMode() & 0o7777;
}

test "recording id hex round-trip, zero and non-canonical rejection, random distinct" {
    const id = testId();
    try testing.expectEqualStrings("1032547698badcfe0123456789abcdef", &id.hex());
    try testing.expect((try RecordingId.parseHex(&id.hex())).eql(id));
    try testing.expectError(error.InvalidRecordingId, RecordingId.fromBytes(@splat(0)));
    try testing.expectError(error.InvalidRecordingId, RecordingId.parseHex("1032547698BADCFE0123456789ABCDEF"));
    try testing.expectError(error.InvalidRecordingId, RecordingId.parseHex("1032"));
    try testing.expectError(error.InvalidRecordingId, RecordingId.parseHex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
    const a = RecordingId.random(testing.io);
    const b = RecordingId.random(testing.io);
    try testing.expect(!a.eql(b) and !a.isZero() and !b.isZero());
}

test "track validation matrix and declaration round-trip" {
    try testing.expectError(error.InvalidTrack, Track.init(0, .audio, "opus", 48_000));
    try testing.expectError(error.InvalidTrack, Track.init(1, .audio, "bad codec!", 48_000));
    try testing.expectError(error.InvalidTrack, Track.init(1, .audio, "", 48_000));
    try testing.expectError(error.InvalidTrack, Track.init(1, .audio, "opus", 0));
    try testing.expectError(error.InvalidTrack, (try Track.init(2, .video, "vp8", 90_000)).validate()); // dimensions required
    try testing.expectError(error.InvalidTrack, (try audioTrack()).withDimensions(1, 1));
    try testing.expectError(error.InvalidTrack, (try Track.init(3, .caption, "webvtt", 0)).withLanguage("en US!"));
    const screen = try (try Track.init(4, .screen, "cadencevis", 90_000)).withDimensions(1920, 1080);
    const caption = try (try Track.init(5, .caption, "webvtt", 0)).withLanguage("en-US");
    for ([_]Track{ try audioTrack(), try videoTrack(), screen, caption }) |t| {
        const payload = try encodeTrackDecl(testing.allocator, t);
        defer testing.allocator.free(payload);
        try testing.expect((try decodeTrackDecl(t.id, payload)).eql(t));
        var bad = try testing.allocator.dupe(u8, payload);
        defer testing.allocator.free(bad);
        bad[3] = 1;
        try testing.expectError(error.InvalidTrack, decodeTrackDecl(t.id, bad));
    }
    try testing.expect(TrackKind.video.needsKeyframe() and TrackKind.screen.needsKeyframe());
    try testing.expect(!TrackKind.audio.needsKeyframe() and !TrackKind.caption.needsKeyframe());
}

test "header round-trip and strict rejection" {
    const header: Header = .{ .recording_id = testId(), .segment_index = 7, .created_unix_ms = -5, .flags = flag_mac_chain };
    const bytes = encodeHeader(header);
    try testing.expectEqualDeep(header, try parseHeader(&bytes));
    var bad = bytes;
    bad[0] = 'X';
    try testing.expectError(error.InvalidHeader, parseHeader(&bad));
    bad = bytes;
    std.mem.writeInt(u16, bad[8..10], 2, .little);
    try testing.expectError(error.UnsupportedVersion, parseHeader(&bad));
    bad = bytes;
    bad[44] = 1;
    try testing.expectError(error.InvalidHeader, parseHeader(&bad));
    bad = bytes;
    std.mem.writeInt(u32, bad[12..16], 2, .little);
    try testing.expectError(error.InvalidHeader, parseHeader(&bad));
    try testing.expectError(error.InvalidHeader, parseHeader(bytes[0..20]));
    // Scanner agrees: bad header is no valid prefix at all.
    const s = scan("not a journal", null);
    try testing.expectEqual(StopReason.bad_header, s.stop_reason);
    try testing.expectEqual(@as(usize, 0), s.valid_bytes);
}

test "keyframe gate: video/screen gated, audio/caption pass, discontinuity re-arms" {
    var gate: KeyframeGate = .{};
    try gate.register(try audioTrack());
    try gate.register(try videoTrack());
    try gate.register(try Track.init(3, .caption, "webvtt", 0));
    try testing.expectEqual(KeyframeGate.Decision.accept, gate.observe(1, false, false));
    try testing.expectEqual(KeyframeGate.Decision.accept, gate.observe(3, false, false));
    try testing.expectEqual(KeyframeGate.Decision.drop_awaiting_keyframe, gate.observe(2, false, false));
    try testing.expectEqual(KeyframeGate.Decision.accept, gate.observe(2, true, false));
    try testing.expectEqual(KeyframeGate.Decision.accept, gate.observe(2, false, false));
    try testing.expectEqual(KeyframeGate.Decision.drop_awaiting_keyframe, gate.observe(2, false, true));
    try testing.expectEqual(KeyframeGate.Decision.drop_awaiting_keyframe, gate.observe(2, false, false));
    try testing.expectEqual(KeyframeGate.Decision.accept, gate.observe(2, true, true));
    gate.resetTrack(2);
    try testing.expect(!gate.isOpen(2));
    try testing.expectEqual(@as(u64, 3), gate.dropped);
    var disabled: KeyframeGate = .{ .enabled = false };
    try disabled.register(try videoTrack());
    try testing.expectEqual(KeyframeGate.Decision.accept, disabled.observe(2, false, false));
}

test "queue: FIFO, wraparound, bounds, byte budget, closed, ownership, peek" {
    var q = try Queue.init(testing.allocator, 3, 9, 4);
    defer q.deinit();
    try testing.expect(q.isEmpty() and q.peek() == null and q.pop() == null);
    try testing.expectEqual(PushOutcome.queued, q.tryPush(.{ .track_id = 1, .pts_us = 0, .payload = "aa" }));
    try testing.expectEqual(PushOutcome.queued, q.tryPush(.{ .track_id = 1, .pts_us = 1, .payload = "bbbb" }));
    try testing.expectEqual(@as(usize, 6), q.queuedBytes());
    try testing.expectEqual(PushOutcome.too_large, q.tryPush(.{ .track_id = 1, .pts_us = 2, .payload = "12345" }));
    try testing.expectEqual(PushOutcome.invalid, q.tryPush(.{ .track_id = 0, .pts_us = 2, .payload = "x" }));
    try testing.expectEqual(PushOutcome.invalid, q.tryPush(.{ .track_id = 1, .pts_us = -1, .payload = "x" }));
    try testing.expectEqual(PushOutcome.invalid, q.tryPush(.{ .track_id = 1, .pts_us = 2, .payload = "" }));
    try testing.expectEqual(PushOutcome.byte_budget, q.tryPush(.{ .track_id = 1, .pts_us = 2, .payload = "ccccx"[0..4] }));
    // peek does not consume
    try testing.expectEqualStrings("aa", q.peek().?.payload);
    try testing.expectEqualStrings("aa", q.peek().?.payload);
    var first = q.pop().?;
    try testing.expectEqualStrings("aa", first.payload);
    first.deinit(testing.allocator);
    try testing.expectEqual(PushOutcome.queued, q.tryPush(.{ .track_id = 1, .pts_us = 2, .payload = "cc" }));
    try testing.expectEqual(PushOutcome.queued, q.tryPush(.{ .track_id = 1, .pts_us = 3, .payload = "dd" })); // wraps, now full (3 items)
    // byte budget would also trip; use empty-ish check after drain for `.full`
    while (q.pop()) |item| {
        var owned_item = item;
        owned_item.deinit(testing.allocator);
    }
    for (0..3) |i| try testing.expectEqual(PushOutcome.queued, q.tryPush(.{ .track_id = 1, .pts_us = @intCast(i), .payload = "z" }));
    try testing.expectEqual(PushOutcome.full, q.tryPush(.{ .track_id = 1, .pts_us = 9, .payload = "z" }));
    // failed owned push keeps ownership with the caller
    const owned = try testing.allocator.dupe(u8, "q");
    try testing.expectEqual(PushOutcome.full, q.tryPushOwned(.{ .track_id = 1, .pts_us = 10 }, owned));
    testing.allocator.free(owned);
    while (q.pop()) |item| {
        var owned_item = item;
        owned_item.deinit(testing.allocator);
    }
    q.close();
    try testing.expectEqual(PushOutcome.closed, q.tryPush(.{ .track_id = 1, .pts_us = 11, .payload = "z" }));
    try testing.expect(q.dropped_full.load(.monotonic) >= 2);
}

test "queue: allocation failure is an outcome, and threaded SPSC preserves order" {
    var q = try Queue.init(testing.allocator, 4, 1 << 20, 1024);
    defer q.deinit();
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const saved = q.allocator;
    q.allocator = failing.allocator();
    try testing.expectEqual(PushOutcome.out_of_memory, q.tryPush(.{ .track_id = 1, .pts_us = 0, .payload = "x" }));
    q.allocator = saved;

    const Ctx = struct {
        q: *Queue,
        n: usize,
        fn produce(ctx: *@This()) void {
            for (0..ctx.n) |i| {
                while (true) {
                    const out = ctx.q.tryPush(.{ .track_id = 1, .pts_us = @intCast(i), .payload = "pkt" });
                    if (out == .queued) break;
                    std.atomic.spinLoopHint();
                }
            }
            ctx.q.close();
        }
    };
    var ctx: Ctx = .{ .q = &q, .n = 500 };
    const thread = try std.Thread.spawn(.{}, Ctx.produce, .{&ctx});
    var expect_pts: i64 = 0;
    while (expect_pts < 500) {
        if (q.pop()) |item| {
            var owned_item = item;
            try testing.expectEqual(expect_pts, owned_item.pts_us);
            owned_item.deinit(testing.allocator);
            expect_pts += 1;
        } else std.atomic.spinLoopHint();
    }
    thread.join();
    try testing.expect(q.isEmpty() and q.isClosed());
}

test "writer: four tracks, finalize renames 0600, scan and manifest verify" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var w = try testWriter(tmp.dir, testConfig());
    try w.declareTrack(try audioTrack());
    try w.declareTrack(try videoTrack());
    try w.declareTrack(try (try Track.init(3, .screen, "cadencevis", 90_000)).withDimensions(800, 600));
    try w.declareTrack(try (try Track.init(4, .caption, "webvtt", 0)).withLanguage("en"));
    try testing.expectEqual(WriteOutcome.written, try w.writePacket(.{ .track_id = 1, .pts_us = 0, .duration_us = 20_000, .payload = "audio-0" }));
    try testing.expectEqual(WriteOutcome.dropped_awaiting_keyframe, try w.writePacket(.{ .track_id = 2, .pts_us = 0, .duration_us = 33_333, .payload = "delta" }));
    try testing.expectEqual(WriteOutcome.written, try w.writePacket(.{ .track_id = 2, .pts_us = 0, .duration_us = 33_333, .keyframe = true, .payload = "key-0" }));
    try testing.expectEqual(WriteOutcome.written, try w.writePacket(.{ .track_id = 2, .pts_us = 33_333, .duration_us = 33_333, .payload = "delta-1" }));
    try testing.expectEqual(WriteOutcome.written, try w.writePacket(.{ .track_id = 3, .pts_us = 10_000, .keyframe = true, .payload = "screen-0" }));
    try testing.expectEqual(WriteOutcome.written, try w.writePacket(.{ .track_id = 4, .pts_us = 10_000, .duration_us = 500_000, .payload = "hello captions" }));
    try w.writeGap(1, 40_000, .queue_full, 2);
    // gate drops leave last_pts untouched: an audio pts after the gap is fine
    try testing.expectEqual(WriteOutcome.written, try w.writePacket(.{ .track_id = 1, .pts_us = 40_000, .duration_us = 20_000, .payload = "audio-1" }));
    const manifest = try w.finalize();
    w.deinit();
    try testing.expectEqualStrings("rec-1032547698badcfe0123456789abcdef-s000000.onyxrec", manifest.fileName());
    try testing.expect(isOwnedSegmentName(manifest.fileName()));
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(testing.io, "rec-1032547698badcfe0123456789abcdef-s000000.part", .{}));
    if (comptime builtin.os.tag != .windows) try testing.expectEqual(@as(std.posix.mode_t, 0o600), try fileMode(tmp.dir, manifest.fileName()));
    const bytes = try tmp.dir.readFileAlloc(testing.io, manifest.fileName(), testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(bytes);
    const s = scan(bytes, null);
    try testing.expectEqual(StopReason.end, s.stop_reason);
    try testing.expect(s.finalized);
    try testing.expectEqual(@as(u64, 6), s.packet_count);
    try testing.expectEqual(@as(u64, 1), s.gap_count);
    try testing.expectEqual(@as(usize, 4), s.track_count);
    try testing.expectEqual(@as(i64, 510_000), s.durationUs());
    try testing.expect(verifyManifest(bytes, &manifest, null));
    // Independent SHA-256 over the file bytes matches the manifest.
    var digest: [32]u8 = undefined;
    Sha256.hash(bytes, &digest, .{});
    try testing.expectEqualSlices(u8, &digest, &manifest.sha256);
    const end = s.segment_end.?;
    try testing.expectEqual(@as(u64, 6), end.packet_count);
    try testing.expectEqual(@as(u64, 1), end.dropped_gate);
    // Iterator payloads come back in write order.
    var it = Iterator.init(bytes, null);
    var payloads: std.ArrayList([]const u8) = .empty;
    defer payloads.deinit(testing.allocator);
    while (it.next()) |rec| if (rec.record_type == .packet) try payloads.append(testing.allocator, rec.payload);
    try testing.expectEqualStrings("audio-0", payloads.items[0]);
    try testing.expectEqualStrings("key-0", payloads.items[1]);
    try testing.expectEqualStrings("hello captions", payloads.items[4]);
    // Manifest JSON carries the same facts and writes as a 0600 sidecar.
    try writeManifestFile(testing.allocator, testing.io, tmp.dir, &manifest);
    var man_buf: [96]u8 = undefined;
    const man_name = try manifestName(&man_buf, testId(), 0);
    if (comptime builtin.os.tag != .windows) try testing.expectEqual(@as(std.posix.mode_t, 0o600), try fileMode(tmp.dir, man_name));
    const json = try tmp.dir.readFileAlloc(testing.io, man_name, testing.allocator, .limited(8192));
    defer testing.allocator.free(json);
    try testing.expect(std.mem.indexOf(u8, json, "\"sha256\":\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, &manifest.sha256Hex()) != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"kind\":\"caption\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"kind\":\"screen\"") != null);
}

test "writer: refusals leave the journal byte-identical" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var w = try testWriter(tmp.dir, testConfig());
    defer w.deinit();
    try w.declareTrack(try audioTrack());
    try testing.expectEqual(WriteOutcome.written, try w.writePacket(.{ .track_id = 1, .pts_us = 100, .payload = "a" }));
    const before = w.bytes_written;
    try testing.expectError(error.UnknownTrack, w.writePacket(.{ .track_id = 9, .pts_us = 100, .payload = "a" }));
    try testing.expectError(error.OutOfOrderPts, w.writePacket(.{ .track_id = 1, .pts_us = 99, .payload = "a" }));
    try testing.expectError(error.InvalidPacket, w.writePacket(.{ .track_id = 1, .pts_us = 100, .payload = "" }));
    try testing.expectError(error.InvalidPacket, w.writePacket(.{ .track_id = 1, .pts_us = -1, .payload = "a" }));
    const big = try testing.allocator.alloc(u8, 4097);
    defer testing.allocator.free(big);
    try testing.expectError(error.PacketTooLarge, w.writePacket(.{ .track_id = 1, .pts_us = 100, .payload = big }));
    try testing.expectError(error.DuplicateTrack, w.declareTrack(try audioTrack()));
    try testing.expectEqual(before, w.bytes_written);
    const part = try tmp.dir.readFileAlloc(testing.io, w.partNameSlice(), testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(part);
    const s = scan(part, null);
    try testing.expectEqual(StopReason.end, s.stop_reason);
    try testing.expectEqual(@as(u64, 1), s.packet_count);
    try testing.expect(!s.finalized); // deinit without finalize: valid but unsealed
}

test "writer: segment-full, duration cap, and cross-rotation quota" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const decl_payload = track_decl_fixed_len + "cadencevox".len;
    const one_packet_segment = header_len + frameLen(decl_payload) + frameLen(4) + endFrameLen();
    var cfg: Config = .{
        .max_segment_bytes = one_packet_segment,
        .max_total_bytes = one_packet_segment + header_len + frameLen(decl_payload) + endFrameLen(),
        .max_duration_us = 1000,
        .max_packet_bytes = 64,
    };
    try cfg.validate();
    var w = try testWriter(tmp.dir, cfg);
    defer w.deinit();
    try w.declareTrack(try audioTrack());
    try testing.expectEqual(WriteOutcome.written, try w.writePacket(.{ .track_id = 1, .pts_us = 0, .duration_us = 400, .payload = "aaaa" }));
    try testing.expectError(error.SegmentFull, w.writePacket(.{ .track_id = 1, .pts_us = 400, .duration_us = 400, .payload = "bbbb" }));
    // The end-frame reserve means finalize still fits exactly.
    const sealed = try w.rotate();
    try testing.expectEqual(one_packet_segment, sealed.bytes);
    // Duration cap is reported before quota for the over-duration packet...
    try testing.expectError(error.DurationCapExceeded, w.writePacket(.{ .track_id = 1, .pts_us = 700, .duration_us = 400, .payload = "cccc" }));
    // ...and an in-duration packet now hits the whole-recording quota.
    try testing.expectError(error.QuotaExceeded, w.writePacket(.{ .track_id = 1, .pts_us = 400, .duration_us = 400, .payload = "dddd" }));
    const empty = try w.finalize();
    try testing.expectEqual(@as(u64, 0), empty.packet_count);
    try testing.expectEqual(@as(u32, 1), empty.segment_index);
}

test "writer: rotation re-emits declarations and re-arms keyframe gates" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var w = try testWriter(tmp.dir, testConfig());
    defer w.deinit();
    try w.declareTrack(try videoTrack());
    try testing.expectEqual(WriteOutcome.written, try w.writePacket(.{ .track_id = 2, .pts_us = 0, .keyframe = true, .payload = "k0" }));
    const first = try w.rotate();
    try testing.expectEqual(@as(u64, 1), first.packet_count);
    try testing.expectEqual(WriteOutcome.dropped_awaiting_keyframe, try w.writePacket(.{ .track_id = 2, .pts_us = 100, .payload = "d1" }));
    try testing.expectEqual(WriteOutcome.written, try w.writePacket(.{ .track_id = 2, .pts_us = 100, .keyframe = true, .payload = "k1" }));
    const second = try w.finalize();
    try testing.expectEqual(@as(u32, 1), second.segment_index);
    try testing.expectEqual(@as(u64, 1), second.packet_count);
    for ([_]Manifest{ first, second }) |m| {
        const bytes = try tmp.dir.readFileAlloc(testing.io, m.fileName(), testing.allocator, .limited(1 << 20));
        defer testing.allocator.free(bytes);
        try testing.expect(verifyManifest(bytes, &m, null));
        try testing.expectEqual(testId().bytes, m.recording_id.bytes);
    }
    try testing.expectEqual(@as(u32, 2), w.stats.segments_finalized);
}

test "drainQueue: gate drops consume and segment-full rotates automatically" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = testConfig();
    cfg.max_segment_bytes = header_len + frameLen(track_decl_fixed_len + "cadencevis".len) + frameLen(2) + endFrameLen();
    cfg.max_total_bytes = cfg.max_segment_bytes * 4;
    var w = try testWriter(tmp.dir, cfg);
    defer w.deinit();
    try w.declareTrack(try videoTrack());
    var q = try Queue.init(testing.allocator, 8, 4096, 64);
    defer q.deinit();
    try testing.expectEqual(PushOutcome.queued, q.tryPush(.{ .track_id = 2, .pts_us = 0, .payload = "d0" })); // gate drop
    try testing.expectEqual(PushOutcome.queued, q.tryPush(.{ .track_id = 2, .pts_us = 0, .keyframe = true, .payload = "k0" })); // fills segment
    try testing.expectEqual(PushOutcome.queued, q.tryPush(.{ .track_id = 2, .pts_us = 10, .payload = "d1" })); // stays queued
    try testing.expectEqual(@as(usize, 1), try w.drainQueue(&q, 8));
    // After automatic rotation the gate re-armed, consuming d1 as a drop.
    try testing.expectEqual(@as(u32, 1), w.segment_index);
    try testing.expect(q.isEmpty());
    _ = try w.finalize();
}

fn buildFixture(dir: std.Io.Dir, config: Config) !Manifest {
    var w = try testWriter(dir, config);
    defer w.deinit();
    try w.declareTrack(try audioTrack());
    _ = try w.writePacket(.{ .track_id = 1, .pts_us = 0, .duration_us = 10, .payload = "one" });
    _ = try w.writePacket(.{ .track_id = 1, .pts_us = 10, .duration_us = 10, .payload = "two" });
    _ = try w.writePacket(.{ .track_id = 1, .pts_us = 20, .duration_us = 10, .payload = "three" });
    return w.finalize();
}

test "scan: torn tail at every cut keeps a valid prefix; recoverFile truncates" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const manifest = try buildFixture(tmp.dir, testConfig());
    const bytes = try tmp.dir.readFileAlloc(testing.io, manifest.fileName(), testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(bytes);
    // Frame boundaries: truncating anywhere must never report corruption or
    // a valid prefix beyond a whole number of frames.
    var cut: usize = header_len;
    while (cut <= bytes.len) : (cut += 1) {
        const s = scan(bytes[0..cut], null);
        try testing.expect(s.stop_reason == .end or s.stop_reason == .torn_tail);
        try testing.expect(s.valid_bytes <= cut);
        const prefix = scan(bytes[0..s.valid_bytes], null);
        try testing.expectEqual(StopReason.end, prefix.stop_reason);
        try testing.expectEqualSlices(u8, &s.sha256, &prefix.sha256);
    }
    const partial = scan(bytes[0 .. bytes.len - 5], null);
    try testing.expectEqual(StopReason.torn_tail, partial.stop_reason);
    try testing.expect(!partial.finalized);
    // recoverFile on a torn .part copy cuts to the same prefix.
    var name_buf: [96]u8 = undefined;
    const part_name = try partName(&name_buf, testId(), 0);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = part_name, .data = bytes[0 .. bytes.len - 5] });
    const recovery = try recoverFile(testing.allocator, testing.io, tmp.dir, part_name, null, 1 << 20);
    try testing.expect(recovery.truncated);
    const after = try tmp.dir.readFileAlloc(testing.io, part_name, testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(after);
    try testing.expectEqual(recovery.scan.valid_bytes, after.len);
    try testing.expectEqual(StopReason.end, scan(after, null).stop_reason);
    // A clean finalized file is left untouched; foreign names are refused.
    const clean = try recoverFile(testing.allocator, testing.io, tmp.dir, manifest.fileName(), null, 1 << 20);
    try testing.expect(!clean.truncated and clean.scan.finalized);
    try testing.expectError(error.InvalidName, recoverFile(testing.allocator, testing.io, tmp.dir, "alice-#chan.part", null, 1024));
}

test "scan: payload, crc, chain, and length tampering all stop the prefix" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const manifest = try buildFixture(tmp.dir, testConfig());
    const original = try tmp.dir.readFileAlloc(testing.io, manifest.fileName(), testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(original);
    const baseline = scan(original, null);
    try testing.expectEqual(@as(u64, 3), baseline.packet_count);
    // Flip a payload byte in the last packet: CRC refuses, prefix holds 2.
    {
        const copy = try testing.allocator.dupe(u8, original);
        defer testing.allocator.free(copy);
        var it = Iterator.init(copy, null);
        var last_packet: RecordView = undefined;
        while (it.next()) |rec| if (rec.record_type == .packet) {
            last_packet = rec;
        };
        copy[last_packet.offset + length_len + frame_fixed_len] ^= 0xff;
        const s = scan(copy, null);
        try testing.expectEqual(StopReason.corrupt_crc, s.stop_reason);
        try testing.expectEqual(@as(u64, 2), s.packet_count);
        try testing.expect(!verifyManifest(copy, &manifest, null));
    }
    // Rewrite a frame with a correct CRC but a wrong chain (attacker who
    // recomputes CRCs): build via encodeFrameAlloc from a false genesis.
    {
        const decl_end = header_len + frameLen(track_decl_fixed_len + "cadencevox".len);
        var forged: std.ArrayList(u8) = .empty;
        defer forged.deinit(testing.allocator);
        try forged.appendSlice(testing.allocator, original[0..decl_end]);
        const wrong_prev: [32]u8 = @splat(9);
        const frame = try encodeFrameAlloc(testing.allocator, 1, .packet, 1, 0, 0, 10, "one", &wrong_prev, null);
        defer testing.allocator.free(frame.bytes);
        try forged.appendSlice(testing.allocator, frame.bytes);
        const s = scan(forged.items, null);
        try testing.expectEqual(StopReason.corrupt_chain, s.stop_reason);
        try testing.expectEqual(@as(u64, 0), s.packet_count);
    }
    // Absurd declared length is a length failure, not a huge allocation.
    {
        const copy = try testing.allocator.dupe(u8, original);
        defer testing.allocator.free(copy);
        std.mem.writeInt(u32, copy[header_len..][0..4], std.math.maxInt(u32), .little);
        try testing.expectEqual(StopReason.bad_length, scan(copy, null).stop_reason);
    }
    // Trailing garbage after segment_end is not a clean finalized file.
    {
        var trailed: std.ArrayList(u8) = .empty;
        defer trailed.deinit(testing.allocator);
        try trailed.appendSlice(testing.allocator, original);
        try trailed.appendSlice(testing.allocator, "junkjunk");
        const s = scan(trailed.items, null);
        try testing.expect(s.stop_reason != .end);
        try testing.expect(!verifyManifest(trailed.items, &manifest, null));
    }
}

test "MAC chain: right key verifies, missing and wrong keys refuse" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const key: [32]u8 = @splat(0x5a);
    var cfg = testConfig();
    cfg.mac_key = key;
    const manifest = try buildFixture(tmp.dir, cfg);
    try testing.expect(manifest.mac_chain);
    const bytes = try tmp.dir.readFileAlloc(testing.io, manifest.fileName(), testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(bytes);
    try testing.expectEqual(StopReason.end, scan(bytes, key).stop_reason);
    try testing.expectEqual(StopReason.missing_mac_key, scan(bytes, null).stop_reason);
    try testing.expectEqual(header_len, scan(bytes, null).valid_bytes);
    try testing.expectEqual(StopReason.corrupt_chain, scan(bytes, @splat(0xa5)).stop_reason);
    try testing.expect(verifyManifest(bytes, &manifest, key));
    try testing.expect(!verifyManifest(bytes, &manifest, null));
}

test "private dir is 0700, broader pre-existing dir refused, abort deletes part" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const rec = try ensurePrivateDir(tmp.dir, testing.io, "recordings");
    defer rec.close(testing.io);
    if (comptime builtin.os.tag != .windows) {
        const stat = try tmp.dir.statFile(testing.io, "recordings", .{});
        try testing.expectEqual(@as(std.posix.mode_t, 0o700), stat.permissions.toMode() & 0o7777);
    }
    // Re-opening the same private dir succeeds; a broad one is refused.
    const again = try ensurePrivateDir(tmp.dir, testing.io, "recordings");
    again.close(testing.io);
    if (comptime builtin.os.tag != .windows) {
        try tmp.dir.createDir(testing.io, "broad", .fromMode(0o755));
        const broad = try tmp.dir.openDir(testing.io, "broad", .{ .iterate = true });
        defer broad.close(testing.io);
        // Directory creation obeys the caller's umask. Make this fixture
        // explicitly broad even under the service's private 0077 policy.
        try broad.setPermissions(testing.io, .fromMode(0o755));
        try testing.expectError(error.UnprotectedDirectory, ensurePrivateDir(tmp.dir, testing.io, "broad"));
    }
    try testing.expectError(error.InvalidName, ensurePrivateDir(tmp.dir, testing.io, "a/b"));
    try testing.expectError(error.InvalidName, ensurePrivateDir(tmp.dir, testing.io, ".."));
    var w = try testWriter(rec, testConfig());
    try w.declareTrack(try audioTrack());
    var name_buf: [96]u8 = undefined;
    const name = try partName(&name_buf, testId(), 0);
    try testing.expect((try rec.statFile(testing.io, name, .{})).size > 0);
    w.abort();
    try testing.expectError(error.FileNotFound, rec.statFile(testing.io, name, .{}));
    w.deinit();
}

test "scan: declaration after a packet is rejected even with a valid chain" {
    const header: Header = .{ .recording_id = testId(), .segment_index = 0, .created_unix_ms = 0, .flags = 0 };
    const header_bytes = encodeHeader(header);
    var journal: std.ArrayList(u8) = .empty;
    defer journal.deinit(testing.allocator);
    try journal.appendSlice(testing.allocator, &header_bytes);
    var chain = chainGenesis(&header_bytes);
    var seq: u64 = 0;
    const decl = try encodeTrackDecl(testing.allocator, try audioTrack());
    defer testing.allocator.free(decl);
    for ([_]struct { t: RecordType, id: u16, payload: []const u8 }{
        .{ .t = .track_decl, .id = 1, .payload = decl },
        .{ .t = .packet, .id = 1, .payload = "one" },
        .{ .t = .track_decl, .id = 1, .payload = decl },
    }) |step| {
        const frame = try encodeFrameAlloc(testing.allocator, seq, step.t, step.id, 0, 0, 0, step.payload, &chain, null);
        defer testing.allocator.free(frame.bytes);
        chain = frame.chain;
        seq += 1;
        try journal.appendSlice(testing.allocator, frame.bytes);
    }
    const s = scan(journal.items, null);
    try testing.expectEqual(StopReason.bad_record, s.stop_reason);
    try testing.expectEqual(@as(u64, 1), s.packet_count);
}

test "config validation and owned-name grammar" {
    try testing.expectError(error.InvalidConfig, (Config{ .max_segment_bytes = 8, .max_total_bytes = 16 }).validate());
    try testing.expectError(error.InvalidConfig, (Config{ .max_segment_bytes = 1 << 20, .max_total_bytes = 1 << 19 }).validate());
    try testing.expectError(error.InvalidConfig, (Config{ .max_segment_bytes = 1 << 20, .max_total_bytes = 1 << 20, .max_packet_bytes = 0 }).validate());
    try testing.expectError(error.InvalidConfig, (Config{ .max_segment_bytes = 1 << 20, .max_total_bytes = 1 << 20, .max_duration_us = -1 }).validate());
    try testing.expectError(error.InvalidConfig, Queue.init(testing.allocator, 0, 10, 4));
    try testing.expect(isOwnedSegmentName("rec-1032547698badcfe0123456789abcdef-s000042.onyxrec"));
    try testing.expect(isOwnedSegmentName("rec-1032547698badcfe0123456789abcdef-s000042.part"));
    try testing.expect(!isOwnedSegmentName("rec-Alice-#chan-s000042.onyxrec"));
    try testing.expect(!isOwnedSegmentName("rec-1032547698badcfe0123456789abcdef-s42.onyxrec"));
    try testing.expect(!isOwnedSegmentName("../rec-1032547698badcfe0123456789abcdef-s000042.part"));
}

test "drainQueue: late participants rotate with durable inline track metadata" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var w = try testWriter(tmp.dir, testConfig());
    defer w.deinit();
    var q = try Queue.init(testing.allocator, 4, 4096, 1024);
    defer q.deinit();
    var first = try audioTrack();
    try testing.expectEqual(PushOutcome.queued, q.tryPushTrack(first, .{ .track_id = 1, .pts_us = 0, .payload = "alice" }));
    first.codec_buf[0] = 'X'; // staged declaration owns the original bytes
    try testing.expectEqual(@as(usize, 1), try w.drainQueue(&q, 8));
    const second = try Track.init(2, .caption, "text", 0);
    try testing.expectEqual(PushOutcome.queued, q.tryPushTrack(second, .{ .track_id = 2, .pts_us = 1, .payload = "bob" }));
    try testing.expectEqual(@as(usize, 1), try w.drainQueue(&q, 8));
    try testing.expectEqual(@as(u32, 1), w.segment_index);
    const last = try w.finalize();
    try testing.expectEqual(@as(usize, 2), last.track_count);
    try testing.expectEqualStrings("cadencevox", last.tracks[0].codec());
    for (0..2) |i| {
        var buf: [96]u8 = undefined;
        const name = try finalName(&buf, testId(), @intCast(i));
        const bytes = try tmp.dir.readFileAlloc(testing.io, name, testing.allocator, .limited(1 << 20));
        defer testing.allocator.free(bytes);
        const result = scan(bytes, null);
        try testing.expectEqual(StopReason.end, result.stop_reason);
        try testing.expect(result.finalized);
        try testing.expectEqual(@as(u64, 1), result.packet_count);
        try testing.expectEqual(i + 1, result.track_count);
    }
    var buf: [96]u8 = undefined;
    _ = try tmp.dir.statFile(testing.io, try manifestName(&buf, testId(), 0), .{});
}

test "drainQueue: terminal duration and quota caps close without poisoning the head" {
    for ([_]bool{ false, true }) |duration_cap| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var cfg = testConfig();
        cfg.max_segment_bytes = header_len + frameLen(track_decl_fixed_len + "cadencevox".len) + frameLen(1) + endFrameLen();
        cfg.max_total_bytes = if (duration_cap) cfg.max_segment_bytes * 4 else cfg.max_segment_bytes;
        cfg.max_duration_us = if (duration_cap) 5 else 0;
        var w = try testWriter(tmp.dir, cfg);
        defer w.deinit();
        var q = try Queue.init(testing.allocator, 4, 4096, 1024);
        defer q.deinit();
        const track = try audioTrack();
        try testing.expectEqual(PushOutcome.queued, q.tryPushTrack(track, .{ .track_id = 1, .pts_us = 0, .payload = "a" }));
        try testing.expectEqual(PushOutcome.queued, q.tryPushTrack(track, .{ .track_id = 1, .pts_us = 10, .payload = "b" }));
        try testing.expectEqual(@as(usize, 1), try w.drainQueue(&q, 8));
        try testing.expect(q.isClosed());
        try testing.expect(q.isEmpty());
        const manifest = try w.finalize();
        try testing.expectEqual(@as(u64, 1), manifest.packet_count);
        try testing.expect(w.stats.finalized_bytes <= cfg.max_total_bytes);
    }
}

test "drainQueue: invalid head is discarded so following valid media progresses" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var w = try testWriter(tmp.dir, testConfig());
    defer w.deinit();
    var q = try Queue.init(testing.allocator, 4, 4096, 1024);
    defer q.deinit();
    try testing.expectEqual(PushOutcome.queued, q.tryPush(.{ .track_id = 9, .pts_us = 0, .payload = "unknown" }));
    try testing.expectEqual(PushOutcome.queued, q.tryPushTrack(try audioTrack(), .{ .track_id = 1, .pts_us = 0, .payload = "valid" }));
    try testing.expectEqual(@as(usize, 1), try w.drainQueue(&q, 8));
    try testing.expect(q.isEmpty());
    try testing.expectEqual(@as(u64, 1), q.dropped_other.load(.monotonic));
    _ = try w.finalize();
    try testing.expectEqual(PushOutcome.invalid, q.tryPushTrack(try audioTrack(), .{ .track_id = 1, .pts_us = std.math.maxInt(i64), .duration_us = 1, .payload = "overflow" }));
}

test "drainQueue: allocation failure sweep preserves staged track ownership and retry" {
    var reached_success = false;
    for (0..64) |fail_index| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var w = try testWriter(tmp.dir, testConfig());
        defer w.deinit();
        try w.declareTrack(try audioTrack());
        _ = try w.writePacket(.{ .track_id = 1, .pts_us = 0, .payload = "alice" });
        const original_len = w.bytes_written;
        var q = try Queue.init(testing.allocator, 4, 4096, 1024);
        defer q.deinit();
        const track = try Track.init(2, .caption, "text", 0);
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        q.allocator = failing.allocator();
        const push = q.tryPushTrack(track, .{ .track_id = 2, .pts_us = 1, .payload = "bob" });
        q.allocator = testing.allocator;
        if (push == .out_of_memory) {
            try testing.expect(q.isEmpty());
            try testing.expectEqual(PushOutcome.queued, q.tryPushTrack(track, .{ .track_id = 2, .pts_us = 1, .payload = "bob" }));
        } else {
            try testing.expectEqual(PushOutcome.queued, push);
            w.allocator = failing.allocator();
            const result = w.drainQueue(&q, 8);
            w.allocator = testing.allocator;
            if (result) |written| {
                try testing.expectEqual(@as(usize, 1), written);
            } else |err| {
                try testing.expectEqual(error.OutOfMemory, err);
                try testing.expectEqual(@as(usize, 1), q.len());
                try testing.expectEqualStrings("bob", q.peek().?.payload);
                if (w.stats.segments_finalized == 0) {
                    try testing.expectEqual(original_len, w.bytes_written);
                    const prefix = try tmp.dir.readFileAlloc(testing.io, w.partNameSlice(), testing.allocator, .limited(1 << 20));
                    defer testing.allocator.free(prefix);
                    try testing.expectEqual(StopReason.end, scan(prefix, null).stop_reason);
                }
            }
        }
        _ = try w.drainQueue(&q, 8);
        try testing.expect(q.isEmpty());
        const last = try w.finalize();
        try testing.expectEqual(@as(u64, 1), last.packet_count);
        try testing.expectEqual(@as(usize, 2), last.track_count);
        var buf: [96]u8 = undefined;
        const old_bytes = try tmp.dir.readFileAlloc(testing.io, try finalName(&buf, testId(), 0), testing.allocator, .limited(1 << 20));
        defer testing.allocator.free(old_bytes);
        try testing.expect(scan(old_bytes, null).finalized);
        _ = try tmp.dir.statFile(testing.io, try manifestName(&buf, testId(), 0), .{});
        if (!failing.has_induced_failure) {
            reached_success = true;
            break;
        }
    }
    try testing.expect(reached_success);
}

test "drainQueue: successor create failure retains sealed sidecar and fails closed" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var w = try testWriter(tmp.dir, testConfig());
    defer w.deinit();
    try w.declareTrack(try audioTrack());
    _ = try w.writePacket(.{ .track_id = 1, .pts_us = 0, .payload = "alice" });
    var buf: [96]u8 = undefined;
    const conflict = try tmp.dir.createFile(testing.io, try partName(&buf, testId(), 1), .{ .exclusive = true });
    conflict.close(testing.io);
    var q = try Queue.init(testing.allocator, 4, 4096, 1024);
    defer q.deinit();
    try testing.expectEqual(PushOutcome.queued, q.tryPushTrack(try Track.init(2, .caption, "text", 0), .{ .track_id = 2, .pts_us = 1, .payload = "bob" }));
    try testing.expectError(error.PathAlreadyExists, w.drainQueue(&q, 8));
    try testing.expect(w.failed);
    try testing.expect(w.pending_manifest != null);
    try testing.expectEqual(@as(usize, 1), q.len());
    // A retry publishes the retained sidecar, then reports terminal failure.
    try testing.expectError(error.WriterFailed, w.drainQueue(&q, 8));
    _ = try tmp.dir.statFile(testing.io, try manifestName(&buf, testId(), 0), .{});
    const bytes = try tmp.dir.readFileAlloc(testing.io, try finalName(&buf, testId(), 0), testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(bytes);
    try testing.expect(scan(bytes, null).finalized);
}

const FinalizeSyncFault = struct {
    threadlocal var active: ?*FinalizeSyncFault = null;

    directory: bool = true,
    remaining: usize = 0,
    injected: usize = 0,

    fn sync(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
        const fault = active.?;
        // Preserve the real backend userdata for every delegated operation.
        const stat = file.stat(testing.io) catch return error.InputOutput;
        if ((stat.kind == .directory) == fault.directory and fault.remaining != 0) {
            fault.remaining -= 1;
            fault.injected += 1;
            return error.InputOutput;
        }
        return testing.io.vtable.fileSync(userdata, file);
    }
};

test "writer: post-rename sync failure retains final manifest and retries without resealing" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    // Both direct finalization and a rotation interrupted at its seal boundary
    // must leave the same recoverable final segment, with no successor opened.
    for ([_]bool{ false, true }) |rotate| {
        var tmp = testing.tmpDir(.{ .iterate = true });
        defer tmp.cleanup();
        var fault: FinalizeSyncFault = .{ .remaining = 2 };
        FinalizeSyncFault.active = &fault;
        defer FinalizeSyncFault.active = null;
        var vtable = testing.io.vtable.*;
        vtable.fileSync = FinalizeSyncFault.sync;
        const io: std.Io = .{ .userdata = testing.io.userdata, .vtable = &vtable };
        var w = try testWriter(tmp.dir, testConfig());
        w.io = io;
        defer w.deinit();
        try w.declareTrack(try audioTrack());
        _ = try w.writePacket(.{ .track_id = 1, .pts_us = 0, .payload = "accepted" });
        try testing.expectError(error.InputOutput, if (rotate) w.rotate() else w.finalize());
        try testing.expect(w.closed and !w.failed and w.file == null);
        try testing.expect(w.final_manifest != null and w.pending_manifest == null);
        try testing.expectEqual(@as(u32, 0), w.segment_index);
        const retained = w.final_manifest.?;
        const before = try tmp.dir.readFileAlloc(testing.io, retained.fileName(), testing.allocator, .limited(1 << 20));
        defer testing.allocator.free(before);
        try testing.expect(verifyManifest(before, &retained, null));
        try testing.expectError(error.FileNotFound, tmp.dir.statFile(testing.io, w.partNameSlice(), .{}));
        const sealed_stats = w.stats;
        const sealed_seq = w.seq;
        try testing.expectError(error.InputOutput, w.finalize());
        const manifest = try w.finalize();
        try testing.expectEqualSlices(u8, &retained.sha256, &manifest.sha256);
        try testing.expectEqual(retained.bytes, manifest.bytes);
        try testing.expectEqual(retained.packet_count, manifest.packet_count);
        try testing.expectEqual(retained.record_count, manifest.record_count);
        try testing.expectEqualDeep(sealed_stats, w.stats);
        try testing.expectEqual(sealed_seq, w.seq);
        try testing.expectEqual(@as(u32, 1), w.stats.segments_finalized);
        try testing.expectEqual(@as(u64, before.len), w.stats.finalized_bytes);
        try testing.expectEqual(@as(u64, 1), manifest.packet_count);
        try testing.expectEqual(@as(usize, 2), fault.injected);
        const after = try tmp.dir.readFileAlloc(testing.io, manifest.fileName(), testing.allocator, .limited(1 << 20));
        defer testing.allocator.free(after);
        try testing.expectEqualSlices(u8, before, after);

        // A sidecar rename followed by the same failure is also retryable:
        // publication replaces the same sidecar, never inventing a segment.
        fault.remaining = 1;
        try testing.expectError(error.InputOutput, writeManifestFile(testing.allocator, io, tmp.dir, &manifest));
        try writeManifestFile(testing.allocator, io, tmp.dir, &manifest);
        var name_buf: [96]u8 = undefined;
        const sidecar = try tmp.dir.readFileAlloc(testing.io, try manifestName(&name_buf, testId(), 0), testing.allocator, .limited(1 << 20));
        defer testing.allocator.free(sidecar);
        const expected = try manifest.encodeAlloc(testing.allocator);
        defer testing.allocator.free(expected);
        try testing.expectEqualSlices(u8, expected, sidecar);
        var iterator = tmp.dir.iterate();
        var files: usize = 0;
        while (try iterator.next(testing.io)) |_| files += 1;
        try testing.expectEqual(@as(usize, 2), files);
    }
}

test "writer: pre-rename sync and rename failures leave terminal recoverable parts" {
    for ([_]bool{ false, true }) |fail_sync| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var fault: FinalizeSyncFault = .{ .directory = false, .remaining = if (fail_sync) 1 else 0 };
        FinalizeSyncFault.active = &fault;
        defer FinalizeSyncFault.active = null;
        var vtable = testing.io.vtable.*;
        vtable.fileSync = FinalizeSyncFault.sync;
        var w = try testWriter(tmp.dir, testConfig());
        w.io = .{ .userdata = testing.io.userdata, .vtable = &vtable };
        defer w.deinit();
        try w.declareTrack(try audioTrack());
        _ = try w.writePacket(.{ .track_id = 1, .pts_us = 0, .payload = "accepted" });
        var buf: [96]u8 = undefined;
        if (!fail_sync) try tmp.dir.createDir(testing.io, try finalName(&buf, testId(), 0), .default_dir);
        if (w.finalize()) |_| return error.TestUnexpectedResult else |err| {
            if (fail_sync) try testing.expectEqual(error.InputOutput, err);
        }
        try testing.expect(w.failed and w.closed and w.file == null);
        try testing.expect(w.final_manifest == null);
        try testing.expectEqual(@as(u32, 0), w.stats.segments_finalized);
        const before = try tmp.dir.readFileAlloc(testing.io, w.partNameSlice(), testing.allocator, .limited(1 << 20));
        defer testing.allocator.free(before);
        try testing.expect(scan(before, null).finalized);
        try testing.expectError(error.WriterFailed, w.finalize());
        const after = try tmp.dir.readFileAlloc(testing.io, w.partNameSlice(), testing.allocator, .limited(1 << 20));
        defer testing.allocator.free(after);
        try testing.expectEqualSlices(u8, before, after);
    }
}

test "scan: oversized declaration metadata and overflowing packet end fail closed" {
    var bad: [track_decl_fixed_len + max_codec_len + 1]u8 = @splat('a');
    bad[0] = @backingInt(TrackKind.audio);
    bad[1] = max_codec_len + 1;
    bad[2] = 0;
    bad[3] = 0;
    try testing.expectError(error.InvalidTrack, decodeTrackDecl(1, &bad));
    const header = encodeHeader(.{ .recording_id = testId(), .segment_index = 0, .created_unix_ms = 0, .flags = 0 });
    const decl = try encodeTrackDecl(testing.allocator, try audioTrack());
    defer testing.allocator.free(decl);
    const genesis = chainGenesis(&header);
    const track_frame = try encodeFrameAlloc(testing.allocator, 0, .track_decl, 1, 0, 0, 0, decl, &genesis, null);
    defer testing.allocator.free(track_frame.bytes);
    const packet_frame = try encodeFrameAlloc(testing.allocator, 1, .packet, 1, 0, std.math.maxInt(i64), 1, "x", &track_frame.chain, null);
    defer testing.allocator.free(packet_frame.bytes);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(testing.allocator);
    try bytes.appendSlice(testing.allocator, &header);
    try bytes.appendSlice(testing.allocator, track_frame.bytes);
    try bytes.appendSlice(testing.allocator, packet_frame.bytes);
    const result = scan(bytes.items, null);
    try testing.expectEqual(StopReason.bad_record, result.stop_reason);
    try testing.expectEqual(@as(u64, 0), result.packet_count);
}
