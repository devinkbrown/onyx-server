// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SUIMYAKU media control plane.
//!
//! Bounded roster state, SFU forwarding decisions, simulcast layer choice, ABR
//! hints, and codec offer/answer negotiation. Hot paths use inline storage.
const std = @import("std");
const toml = @import("../../proto/toml.zig");

const Allocator = std.mem.Allocator;

// NOTE: the four size constants below are used as COMPTIME array bounds
// (`[max_participant_id_bytes]u8`, `[max_codecs]Codec`, ...). They parameterize
// inline storage and CANNOT be made runtime without reworking those types onto
// the heap, so the corresponding `[media.sfu]` byte/count keys are DEFERRED.
pub const max_participant_id_bytes = 64;
pub const max_rid_bytes = 16;
pub const max_codecs = 8;
pub const max_crypto_suites = 4;

// -- Video / simulcast geometry defaults -------------------------------------

pub const default_max_layer_width: u16 = 3840;
pub const default_max_layer_height: u16 = 2160;
pub const default_max_layer_fps: u8 = 60;
pub const default_receiver_max_fps: u8 = 60;

/// Runtime-tunable simulcast geometry guards (the `SimulcastLayer.init` accept
/// bounds and the default receiver fps ceiling). Defaults equal the historical
/// 4K@60 bounds; `applyToml` overlays the `[media.video]` section.
pub const VideoConfig = struct {
    max_layer_width: u16 = default_max_layer_width,
    max_layer_height: u16 = default_max_layer_height,
    max_layer_fps: u8 = default_max_layer_fps,
    default_receiver_max_fps: u8 = default_receiver_max_fps,
};

/// Overlay `[media.video]` keys from a parsed TOML document onto `cfg`.
pub fn applyTomlVideo(cfg: *VideoConfig, doc: *const toml.Document) void {
    if (doc.getUint("media.video.max_layer_width")) |v| cfg.max_layer_width = @intCast(v);
    if (doc.getUint("media.video.max_layer_height")) |v| cfg.max_layer_height = @intCast(v);
    if (doc.getUint("media.video.max_layer_fps")) |v| cfg.max_layer_fps = @intCast(v);
    if (doc.getUint("media.video.default_receiver_max_fps")) |v| cfg.default_receiver_max_fps = @intCast(v);
}

pub const MediaKind = enum(u2) {
    voice,
    video,
    screen,
};

pub const KindSet = struct {
    bits: u8 = 0,

    pub fn empty() KindSet {
        return .{};
    }

    pub fn of(kind: MediaKind) KindSet {
        var set = KindSet.empty();
        set.insert(kind);
        return set;
    }

    pub fn insert(self: *KindSet, kind: MediaKind) void {
        self.bits |= kindBit(kind);
    }

    pub fn remove(self: *KindSet, kind: MediaKind) void {
        self.bits &= ~kindBit(kind);
    }

    pub fn contains(self: KindSet, kind: MediaKind) bool {
        return (self.bits & kindBit(kind)) != 0;
    }

    pub fn any(self: KindSet) bool {
        return self.bits != 0;
    }

    fn kindBit(kind: MediaKind) u8 {
        return @as(u8, 1) << @intCast(@intFromEnum(kind));
    }
};

pub const ParticipantId = struct {
    bytes: [max_participant_id_bytes]u8 = @splat(0),
    len: u8 = 0,

    pub const Error = error{ EmptyParticipantId, ParticipantIdTooLong, InvalidParticipantId };

    pub fn init(value: []const u8) Error!ParticipantId {
        if (value.len == 0) return error.EmptyParticipantId;
        if (value.len > max_participant_id_bytes) return error.ParticipantIdTooLong;
        for (value) |byte| {
            if (!isIdentityByte(byte)) return error.InvalidParticipantId;
        }

        var id = ParticipantId{};
        id.len = @intCast(value.len);
        @memcpy(id.bytes[0..value.len], value);
        return id;
    }

    pub fn slice(self: *const ParticipantId) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn eql(self: *const ParticipantId, other: *const ParticipantId) bool {
        return self.len == other.len and std.mem.eql(u8, self.slice(), other.slice());
    }
};

/// Validate count before slicing and require the exact canonical spelling/tail.
pub fn validateParticipantId(id: ParticipantId) error{InvalidSnapshot}!void {
    if (id.len == 0 or id.len > max_participant_id_bytes) return error.InvalidSnapshot;
    const canonical = ParticipantId.init(id.bytes[0..id.len]) catch return error.InvalidSnapshot;
    if (!std.meta.eql(id, canonical)) return error.InvalidSnapshot;
}

pub const Participant = struct {
    id: ParticipantId = .{},
    joined: KindSet = .{},
    muted: KindSet = .{},
    speaking: KindSet = .{},

    pub fn canPublish(self: *const Participant, kind: MediaKind) bool {
        return self.joined.contains(kind) and !self.muted.contains(kind);
    }

    pub fn canReceive(self: *const Participant, kind: MediaKind) bool {
        return self.joined.contains(kind);
    }
};

pub const SessionError = ParticipantId.Error || error{ ParticipantCapacityExceeded, ParticipantNotFound, SourceNotPublishing };

pub fn Session(comptime max_participants: usize) type {
    comptime {
        std.debug.assert(max_participants > 0);
    }

    return struct {
        const Self = @This();

        participants: [max_participants]Participant = undefined,
        len: usize = 0,

        /// Source-owned canonical used-prefix DTO. Unused live storage may be
        /// undefined; capture never reads it and the DTO zeroes its tail.
        pub const Snapshot = struct {
            participants: [max_participants]Participant = @splat(.{}),
            len: usize = 0,

            pub fn validate(self: *const Snapshot) error{InvalidSnapshot}!void {
                if (self.len > max_participants) return error.InvalidSnapshot;
                for (self.participants[0..self.len], 0..) |entry, i| {
                    try validateParticipantId(entry.id);
                    if (entry.joined.bits == 0 or (entry.joined.bits | entry.muted.bits | entry.speaking.bits) & ~@as(u8, 7) != 0 or
                        entry.speaking.bits & ~entry.joined.bits != 0 or entry.speaking.bits & entry.muted.bits != 0) return error.InvalidSnapshot;
                    // Muting a kind not joined is supported by setMuted.
                    for (self.participants[0..i]) |prior| if (prior.id.eql(&entry.id)) return error.InvalidSnapshot;
                }
                for (self.participants[self.len..]) |entry| if (!std.meta.eql(entry, Participant{})) return error.InvalidSnapshot;
            }
        };

        pub fn capture(self: *const Self) error{InvalidSnapshot}!Snapshot {
            if (self.len > max_participants) return error.InvalidSnapshot;
            var snapshot: Snapshot = .{ .len = self.len };
            @memcpy(snapshot.participants[0..self.len], self.participants[0..self.len]);
            try snapshot.validate();
            return snapshot;
        }

        pub fn prepareRestore(snapshot: *const Snapshot) error{InvalidSnapshot}!Self {
            try snapshot.validate();
            return .{ .participants = snapshot.participants, .len = snapshot.len };
        }

        pub fn init() Self {
            return .{};
        }

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        pub fn join(self: *Self, id: ParticipantId, kind: MediaKind) SessionError!void {
            if (self.findIndex(&id)) |idx| {
                self.participants[idx].joined.insert(kind);
                return;
            }
            if (self.len == max_participants) return error.ParticipantCapacityExceeded;

            self.participants[self.len] = .{
                .id = id,
                .joined = KindSet.of(kind),
                .muted = .{},
                .speaking = .{},
            };
            self.len += 1;
        }

        pub fn leave(self: *Self, id: ParticipantId, kind: MediaKind) SessionError!void {
            const idx = self.findIndex(&id) orelse return error.ParticipantNotFound;
            self.participants[idx].joined.remove(kind);
            self.participants[idx].muted.remove(kind);
            self.participants[idx].speaking.remove(kind);
            if (!self.participants[idx].joined.any()) self.removeIndex(idx);
        }

        pub fn leaveAll(self: *Self, id: ParticipantId) SessionError!void {
            const idx = self.findIndex(&id) orelse return error.ParticipantNotFound;
            self.removeIndex(idx);
        }

        pub fn setMuted(self: *Self, id: ParticipantId, kind: MediaKind, muted: bool) SessionError!void {
            const entry = self.participantMut(id) orelse return error.ParticipantNotFound;
            if (muted) {
                entry.muted.insert(kind);
                entry.speaking.remove(kind);
            } else {
                entry.muted.remove(kind);
            }
        }

        pub fn setSpeaking(self: *Self, id: ParticipantId, kind: MediaKind, speaking: bool) SessionError!void {
            const entry = self.participantMut(id) orelse return error.ParticipantNotFound;
            if (!entry.canPublish(kind)) return error.SourceNotPublishing;
            if (speaking) {
                entry.speaking.insert(kind);
            } else {
                entry.speaking.remove(kind);
            }
        }

        pub fn participant(self: *const Self, id: ParticipantId) ?*const Participant {
            const idx = self.findIndex(&id) orelse return null;
            return &self.participants[idx];
        }

        pub fn forwardSet(
            self: *const Self,
            source_id: ParticipantId,
            kind: MediaKind,
            policy: RoutePolicy,
        ) SessionError!ForwardSet(max_participants) {
            const source_idx = self.findIndex(&source_id) orelse return error.ParticipantNotFound;
            const source = &self.participants[source_idx];
            if (!source.canPublish(kind)) return error.SourceNotPublishing;
            if (policy.require_speaking and !source.speaking.contains(kind)) {
                return ForwardSet(max_participants).init();
            }

            var out = ForwardSet(max_participants).init();
            for (self.participants[0..self.len], 0..) |candidate, idx| {
                if (idx == source_idx) continue;
                if (!candidate.canReceive(kind)) continue;
                out.append(candidate.id);
            }
            return out;
        }

        fn participantMut(self: *Self, id: ParticipantId) ?*Participant {
            const idx = self.findIndex(&id) orelse return null;
            return &self.participants[idx];
        }

        fn findIndex(self: *const Self, id: *const ParticipantId) ?usize {
            for (self.participants[0..self.len], 0..) |participant_entry, idx| {
                if (participant_entry.id.eql(id)) return idx;
            }
            return null;
        }

        fn removeIndex(self: *Self, idx: usize) void {
            self.len -= 1;
            if (idx != self.len) self.participants[idx] = self.participants[self.len];
        }
    };
}

pub const RoutePolicy = struct {
    require_speaking: bool = false,
};

pub fn ForwardSet(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        recipients: [capacity]ParticipantId = undefined,
        len: usize = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        pub fn contains(self: *const Self, id: ParticipantId) bool {
            for (self.recipients[0..self.len]) |recipient| {
                if (recipient.eql(&id)) return true;
            }
            return false;
        }

        pub fn cloneRecipients(self: *const Self, allocator: Allocator) Allocator.Error![]ParticipantId {
            const out = try allocator.alloc(ParticipantId, self.len);
            @memcpy(out, self.recipients[0..self.len]);
            return out;
        }

        fn append(self: *Self, id: ParticipantId) void {
            self.recipients[self.len] = id;
            self.len += 1;
        }
    };
}

pub const Rid = struct {
    bytes: [max_rid_bytes]u8 = @splat(0),
    len: u8 = 0,

    pub const Error = error{ EmptyRid, RidTooLong, InvalidRid };

    pub fn init(value: []const u8) Error!Rid {
        if (value.len == 0) return error.EmptyRid;
        if (value.len > max_rid_bytes) return error.RidTooLong;
        for (value) |byte| {
            if (!isRidByte(byte)) return error.InvalidRid;
        }

        var rid = Rid{};
        rid.len = @intCast(value.len);
        @memcpy(rid.bytes[0..value.len], value);
        return rid;
    }

    pub fn slice(self: *const Rid) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn eql(self: *const Rid, other: *const Rid) bool {
        return self.len == other.len and std.mem.eql(u8, self.slice(), other.slice());
    }
};

pub const SimulcastLayer = struct {
    rid: Rid,
    bitrate_kbps: u32,
    width: u16,
    height: u16,
    fps: u8,

    pub const Error = Rid.Error || error{ InvalidLayerBitrate, InvalidLayerGeometry, InvalidLayerFps };

    pub fn init(rid: []const u8, bitrate_kbps: u32, width: u16, height: u16, fps: u8) Error!SimulcastLayer {
        return initWithConfig(.{}, rid, bitrate_kbps, width, height, fps);
    }

    /// Config-driven variant: accept-bounds come from `cfg` instead of the
    /// historical hardcoded 4K@60 guards.
    pub fn initWithConfig(cfg: VideoConfig, rid: []const u8, bitrate_kbps: u32, width: u16, height: u16, fps: u8) Error!SimulcastLayer {
        if (bitrate_kbps == 0) return error.InvalidLayerBitrate;
        if (width == 0 or height == 0 or width > cfg.max_layer_width or height > cfg.max_layer_height) {
            return error.InvalidLayerGeometry;
        }
        if (fps == 0 or fps > cfg.max_layer_fps) return error.InvalidLayerFps;
        return .{
            .rid = try Rid.init(rid),
            .bitrate_kbps = bitrate_kbps,
            .width = width,
            .height = height,
            .fps = fps,
        };
    }

    fn score(self: SimulcastLayer) u64 {
        return @as(u64, self.width) * @as(u64, self.height) * @as(u64, self.fps);
    }
};

pub const ReceiverConstraints = struct {
    max_bitrate_kbps: u32,
    max_width: u16,
    max_height: u16,
    max_fps: u8 = default_receiver_max_fps,
};

pub fn LayerDeclaration(comptime capacity: usize) type {
    comptime {
        std.debug.assert(capacity > 0);
    }

    return struct {
        const Self = @This();

        pub const Error = SimulcastLayer.Error || error{ LayerCapacityExceeded, DuplicateRid, InvalidReceiverConstraints };

        layers: [capacity]SimulcastLayer = undefined,
        len: usize = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn add(self: *Self, layer: SimulcastLayer) Error!void {
            if (self.len == capacity) return error.LayerCapacityExceeded;
            for (self.layers[0..self.len]) |existing| {
                if (existing.rid.eql(&layer.rid)) return error.DuplicateRid;
            }
            self.layers[self.len] = layer;
            self.len += 1;
        }

        pub fn select(self: *const Self, constraints: ReceiverConstraints) Error!?SimulcastLayer {
            if (constraints.max_bitrate_kbps == 0 or constraints.max_width == 0 or
                constraints.max_height == 0 or constraints.max_fps == 0)
            {
                return error.InvalidReceiverConstraints;
            }

            var best: ?SimulcastLayer = null;
            for (self.layers[0..self.len]) |layer| {
                if (layer.bitrate_kbps > constraints.max_bitrate_kbps) continue;
                if (layer.width > constraints.max_width or layer.height > constraints.max_height) continue;
                if (layer.fps > constraints.max_fps) continue;

                if (best) |current| {
                    if (layer.score() > current.score() or
                        (layer.score() == current.score() and layer.bitrate_kbps > current.bitrate_kbps))
                    {
                        best = layer;
                    }
                } else {
                    best = layer;
                }
            }
            return best;
        }
    };
}

/// Codecs negotiable on an Undertow media session.
///
/// The native plane is CadenceVox/CadenceVis-first — Onyx Server's own `cadence`
/// implementation (see `cadence_frame`), which is what capable clients use. The
/// standard hardware codecs below exist ONLY as the interop set for the WebRTC
/// mobile gateway (phones that need hardware decode); the SFU still never
/// transcodes, so a mixed call must converge on one shared codec. Native local
/// capability sets should therefore list `cadencevox`/`cadencevis` ahead of the standard
/// codecs so `firstMutualPreferred` prefers our own.
pub const Codec = enum(u8) {
    // Native cadence (primary).
    cadencevox, // CadenceVox audio
    cadencevis, // CadenceVis video
    // Standard hardware codecs — WebRTC mobile-gateway interop only.
    opus,
    vp8,
    vp9,
    av1,
    h264,
};

pub const CryptoSuite = enum(u8) {
    none,
    sframe_aes_gcm,
    dtls_srtp_aes_gcm,
};

pub const CodecSet = struct {
    items: [max_codecs]Codec = undefined,
    len: usize = 0,

    pub const Error = error{ CodecCapacityExceeded, EmptyCodecSet };

    pub fn init(items: []const Codec) Error!CodecSet {
        if (items.len == 0) return error.EmptyCodecSet;
        if (items.len > max_codecs) return error.CodecCapacityExceeded;
        var set = CodecSet{};
        for (items) |codec| set.add(codec) catch {};
        return set;
    }

    pub fn add(self: *CodecSet, codec: Codec) Error!void {
        if (self.contains(codec)) return;
        if (self.len == max_codecs) return error.CodecCapacityExceeded;
        self.items[self.len] = codec;
        self.len += 1;
    }

    pub fn contains(self: *const CodecSet, codec: Codec) bool {
        for (self.items[0..self.len]) |item| {
            if (item == codec) return true;
        }
        return false;
    }

    pub fn firstMutualPreferred(local: *const CodecSet, remote: *const CodecSet) ?Codec {
        for (local.items[0..local.len]) |codec| {
            if (remote.contains(codec)) return codec;
        }
        return null;
    }
};

pub const CryptoSet = struct {
    items: [max_crypto_suites]CryptoSuite = undefined,
    len: usize = 0,

    pub const Error = error{ CryptoCapacityExceeded, EmptyCryptoSet };

    pub fn init(items: []const CryptoSuite) Error!CryptoSet {
        if (items.len == 0) return error.EmptyCryptoSet;
        if (items.len > max_crypto_suites) return error.CryptoCapacityExceeded;
        var set = CryptoSet{};
        for (items) |suite| set.add(suite) catch {};
        return set;
    }

    pub fn add(self: *CryptoSet, suite: CryptoSuite) Error!void {
        if (self.contains(suite)) return;
        if (self.len == max_crypto_suites) return error.CryptoCapacityExceeded;
        self.items[self.len] = suite;
        self.len += 1;
    }

    pub fn contains(self: *const CryptoSet, suite: CryptoSuite) bool {
        for (self.items[0..self.len]) |item| {
            if (item == suite) return true;
        }
        return false;
    }

    pub fn firstMutualPreferred(local: *const CryptoSet, remote: *const CryptoSet) ?CryptoSuite {
        for (local.items[0..local.len]) |suite| {
            if (remote.contains(suite)) return suite;
        }
        return null;
    }
};

pub const MediaCapabilities = struct {
    audio: CodecSet,
    video: CodecSet,
    crypto: CryptoSet,
    max_bitrate_kbps: u32,
    fec: bool = false,
    stereo: bool = false,
    video_enabled: bool = true,
    screen_enabled: bool = true,

    pub const Error = CodecSet.Error || CryptoSet.Error || error{InvalidBitrate};

    pub fn init(
        audio: []const Codec,
        video: []const Codec,
        crypto: []const CryptoSuite,
        max_bitrate_kbps: u32,
    ) Error!MediaCapabilities {
        if (max_bitrate_kbps == 0) return error.InvalidBitrate;
        return .{
            .audio = try CodecSet.init(audio),
            .video = try CodecSet.init(video),
            .crypto = try CryptoSet.init(crypto),
            .max_bitrate_kbps = max_bitrate_kbps,
        };
    }
};

pub const MediaOffer = struct {
    session_id: u64,
    caps: MediaCapabilities,
    wants_video: bool = false,
    wants_screen: bool = false,
    ice_restart: bool = false,
};

pub const MediaAnswer = struct {
    session_id: u64,
    audio: Codec,
    video: ?Codec,
    crypto: CryptoSuite,
    agreed_bitrate_kbps: u32,
    fec: bool,
    stereo: bool,
    video_accepted: bool,
    screen_accepted: bool,
};

pub const NegotiationState = enum {
    idle,
    offered,
    answered,
    rejected,
};

pub const Negotiation = struct {
    state: NegotiationState = .idle,
    offer_value: ?MediaOffer = null,
    answer_value: ?MediaAnswer = null,

    pub const Error = error{ NegotiationBusy, NoPendingOffer, NoMutualAudioCodec, NoMutualCryptoSuite };

    pub fn init() Negotiation {
        return .{};
    }

    pub fn offer(self: *Negotiation, value: MediaOffer) Error!void {
        if (self.state == .offered) return error.NegotiationBusy;
        self.state = .offered;
        self.offer_value = value;
        self.answer_value = null;
    }

    pub fn answer(self: *Negotiation, local: MediaCapabilities) Error!MediaAnswer {
        const pending = self.offer_value orelse return error.NoPendingOffer;
        if (self.state != .offered) return error.NoPendingOffer;

        const audio = CodecSet.firstMutualPreferred(&local.audio, &pending.caps.audio) orelse {
            self.state = .rejected;
            return error.NoMutualAudioCodec;
        };
        const crypto = CryptoSet.firstMutualPreferred(&local.crypto, &pending.caps.crypto) orelse {
            self.state = .rejected;
            return error.NoMutualCryptoSuite;
        };
        const video = if (pending.wants_video and local.video_enabled and pending.caps.video_enabled)
            CodecSet.firstMutualPreferred(&local.video, &pending.caps.video)
        else
            null;

        const answer_value = MediaAnswer{
            .session_id = pending.session_id,
            .audio = audio,
            .video = video,
            .crypto = crypto,
            .agreed_bitrate_kbps = @min(local.max_bitrate_kbps, pending.caps.max_bitrate_kbps),
            .fec = local.fec and pending.caps.fec,
            .stereo = local.stereo and pending.caps.stereo,
            .video_accepted = video != null,
            .screen_accepted = pending.wants_screen and local.screen_enabled and pending.caps.screen_enabled and video != null,
        };

        self.state = .answered;
        self.answer_value = answer_value;
        return answer_value;
    }

    pub fn reset(self: *Negotiation) void {
        self.* = .{};
    }
};

pub const AbrAction = enum {
    hold,
    increase,
    decrease,
    pause,
};

pub const AbrStats = struct {
    current_bitrate_kbps: u32,
    available_bitrate_kbps: u32,
    packet_loss_percent: u8,
    rtt_ms: u16,
    nack_per_second: u16 = 0,
};

pub const AbrConfig = struct {
    min_bitrate_kbps: u32 = 32,
    max_bitrate_kbps: u32 = 6000,
    high_loss_percent: u8 = 8,
    high_rtt_ms: u16 = 350,
    /// NACKs/sec at/above which the link is treated as congested.
    high_nack_per_second: u16 = 20,
    /// Bitrate retained on congestion (loss-driven scale), as a percent.
    congestion_decrease_percent: u32 = 60,
    /// Fraction of available bandwidth targeted on congestion, as a percent.
    congestion_utilization_percent: u32 = 80,
    /// Loss % at/above which FEC level jumps to max while decreasing.
    fec_escalate_loss_percent: u8 = 15,
    /// Spare-bandwidth margin (percent of current) required before increasing.
    increase_headroom_percent: u32 = 25,
    /// Bitrate ramp-up multiplier per increase step, as a percent (>100).
    increase_step_percent: u32 = 115,
    /// Loss % at/below which steady-state holds with no FEC.
    hold_no_fec_loss_percent: u8 = 1,
    /// Maximum FEC redundancy level the ladder may emit.
    max_fec_level: u8 = 3,
};

/// Overlay `[media.abr]` keys from a parsed TOML document onto `cfg`.
pub fn applyTomlAbr(cfg: *AbrConfig, doc: *const toml.Document) void {
    if (doc.getUint("media.abr.min_bitrate_kbps")) |v| cfg.min_bitrate_kbps = @intCast(v);
    if (doc.getUint("media.abr.max_bitrate_kbps")) |v| cfg.max_bitrate_kbps = @intCast(v);
    if (doc.getUint("media.abr.high_loss_percent")) |v| cfg.high_loss_percent = @intCast(v);
    if (doc.getUint("media.abr.high_rtt_ms")) |v| cfg.high_rtt_ms = @intCast(v);
    if (doc.getUint("media.abr.high_nack_per_second")) |v| cfg.high_nack_per_second = @intCast(v);
    if (doc.getUint("media.abr.congestion_decrease_percent")) |v| cfg.congestion_decrease_percent = @intCast(v);
    if (doc.getUint("media.abr.congestion_utilization_percent")) |v| cfg.congestion_utilization_percent = @intCast(v);
    if (doc.getUint("media.abr.fec_escalate_loss_percent")) |v| cfg.fec_escalate_loss_percent = @intCast(v);
    if (doc.getUint("media.abr.increase_headroom_percent")) |v| cfg.increase_headroom_percent = @intCast(v);
    if (doc.getUint("media.abr.increase_step_percent")) |v| cfg.increase_step_percent = @intCast(v);
    if (doc.getUint("media.abr.hold_no_fec_loss_percent")) |v| cfg.hold_no_fec_loss_percent = @intCast(v);
    if (doc.getUint("media.abr.max_fec_level")) |v| cfg.max_fec_level = @intCast(v);
}

pub const AbrHint = struct {
    action: AbrAction,
    target_bitrate_kbps: u32,
    fec_level: u8,
    request_keyframe: bool,
};

pub fn abrHint(config: AbrConfig, stats: AbrStats) error{InvalidAbrInput}!AbrHint {
    if (config.min_bitrate_kbps == 0 or config.max_bitrate_kbps < config.min_bitrate_kbps) {
        return error.InvalidAbrInput;
    }
    if (stats.current_bitrate_kbps == 0 or stats.packet_loss_percent > 100) {
        return error.InvalidAbrInput;
    }

    const available = @min(stats.available_bitrate_kbps, config.max_bitrate_kbps);
    if (available < config.min_bitrate_kbps) {
        return .{
            .action = .pause,
            .target_bitrate_kbps = 0,
            .fec_level = config.max_fec_level,
            .request_keyframe = false,
        };
    }

    const congested = stats.packet_loss_percent >= config.high_loss_percent or
        stats.rtt_ms >= config.high_rtt_ms or stats.nack_per_second >= config.high_nack_per_second;

    if (congested) {
        const loss_scaled = mulDiv(stats.current_bitrate_kbps, config.congestion_decrease_percent, 100);
        const network_scaled = mulDiv(available, config.congestion_utilization_percent, 100);
        // One notch below max for moderate loss; full FEC once loss escalates.
        const decrease_fec: u8 = if (config.max_fec_level > 0) config.max_fec_level - 1 else 0;
        return .{
            .action = .decrease,
            .target_bitrate_kbps = clampBitrate(@min(loss_scaled, network_scaled), config.min_bitrate_kbps, config.max_bitrate_kbps),
            .fec_level = if (stats.packet_loss_percent >= config.fec_escalate_loss_percent) config.max_fec_level else decrease_fec,
            .request_keyframe = true,
        };
    }

    if (available > stats.current_bitrate_kbps + mulDiv(stats.current_bitrate_kbps, config.increase_headroom_percent, 100)) {
        return .{
            .action = .increase,
            .target_bitrate_kbps = clampBitrate(mulDiv(stats.current_bitrate_kbps, config.increase_step_percent, 100), config.min_bitrate_kbps, available),
            .fec_level = if (stats.packet_loss_percent == 0) 0 else 1,
            .request_keyframe = false,
        };
    }

    return .{
        .action = .hold,
        .target_bitrate_kbps = clampBitrate(stats.current_bitrate_kbps, config.min_bitrate_kbps, available),
        .fec_level = if (stats.packet_loss_percent <= config.hold_no_fec_loss_percent) 0 else 1,
        .request_keyframe = false,
    };
}

fn clampBitrate(value: u32, low: u32, high: u32) u32 {
    return @min(@max(value, low), high);
}

fn mulDiv(value: u32, multiplier: u32, divisor: u32) u32 {
    return @intCast((@as(u64, value) * @as(u64, multiplier)) / @as(u64, divisor));
}

fn isIdentityByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_' or
        byte == '.' or byte == '@' or byte == ':';
}

fn isRidByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_';
}

test "join and leave roster state" {
    var session = Session(4).init();
    const alice = try ParticipantId.init("alice");
    const bob = try ParticipantId.init("bob");

    try session.join(alice, .voice);
    try session.join(alice, .video);
    try session.join(bob, .voice);
    try std.testing.expectEqual(@as(usize, 2), session.count());

    const entry = session.participant(alice).?;
    try std.testing.expect(entry.joined.contains(.voice));
    try std.testing.expect(entry.joined.contains(.video));

    try session.setMuted(alice, .voice, true);
    try std.testing.expect(session.participant(alice).?.muted.contains(.voice));

    try session.leave(alice, .voice);
    try std.testing.expect(!session.participant(alice).?.joined.contains(.voice));
    try std.testing.expect(session.participant(alice).?.joined.contains(.video));

    try session.leaveAll(alice);
    try std.testing.expectEqual(@as(usize, 1), session.count());
    try std.testing.expect(session.participant(alice) == null);
}

test "SFU forward set excludes source and muted publisher" {
    var session = Session(4).init();
    const alice = try ParticipantId.init("alice");
    const bob = try ParticipantId.init("bob");
    const carol = try ParticipantId.init("carol");

    try session.join(alice, .voice);
    try session.join(bob, .voice);
    try session.join(carol, .video);

    var route = try session.forwardSet(alice, .voice, .{});
    try std.testing.expectEqual(@as(usize, 1), route.count());
    try std.testing.expect(route.contains(bob));
    try std.testing.expect(!route.contains(alice));
    try std.testing.expect(!route.contains(carol));

    try session.setMuted(alice, .voice, true);
    try std.testing.expectError(error.SourceNotPublishing, session.forwardSet(alice, .voice, .{}));
}

test "simulcast layer selection chooses best layer under constraints" {
    var decl = LayerDeclaration(4).init();
    try decl.add(try SimulcastLayer.init("q", 150, 320, 180, 15));
    try decl.add(try SimulcastLayer.init("h", 900, 1280, 720, 30));
    try decl.add(try SimulcastLayer.init("f", 2500, 1920, 1080, 60));

    const mobile = (try decl.select(.{
        .max_bitrate_kbps = 1000,
        .max_width = 1280,
        .max_height = 720,
        .max_fps = 30,
    })).?;
    try std.testing.expect(std.mem.eql(u8, "h", mobile.rid.slice()));

    const low = (try decl.select(.{
        .max_bitrate_kbps = 200,
        .max_width = 640,
        .max_height = 360,
        .max_fps = 30,
    })).?;
    try std.testing.expect(std.mem.eql(u8, "q", low.rid.slice()));
}

test "codec negotiation selects mutual local preference" {
    var local = try MediaCapabilities.init(
        &.{.opus},
        &.{ .av1, .vp9, .vp8 },
        &.{ .sframe_aes_gcm, .none },
        1500,
    );
    local.fec = true;
    local.stereo = true;

    var remote = try MediaCapabilities.init(
        &.{.opus},
        &.{ .vp8, .vp9 },
        &.{ .none, .sframe_aes_gcm },
        2200,
    );
    remote.fec = true;
    remote.stereo = false;

    var negotiation = Negotiation.init();
    try negotiation.offer(.{
        .session_id = 42,
        .caps = remote,
        .wants_video = true,
        .wants_screen = true,
    });

    const answer_value = try negotiation.answer(local);
    try std.testing.expectEqual(NegotiationState.answered, negotiation.state);
    try std.testing.expectEqual(Codec.opus, answer_value.audio);
    try std.testing.expectEqual(@as(?Codec, Codec.vp9), answer_value.video);
    try std.testing.expectEqual(CryptoSuite.sframe_aes_gcm, answer_value.crypto);
    try std.testing.expectEqual(@as(u32, 1500), answer_value.agreed_bitrate_kbps);
    try std.testing.expect(answer_value.fec);
    try std.testing.expect(!answer_value.stereo);
    try std.testing.expect(answer_value.screen_accepted);
}

test "ABR hint lowers bitrate on congestion" {
    const hint = try abrHint(.{}, .{
        .current_bitrate_kbps = 1200,
        .available_bitrate_kbps = 900,
        .packet_loss_percent = 12,
        .rtt_ms = 120,
        .nack_per_second = 2,
    });

    try std.testing.expectEqual(AbrAction.decrease, hint.action);
    try std.testing.expectEqual(@as(u32, 720), hint.target_bitrate_kbps);
    try std.testing.expectEqual(@as(u8, 2), hint.fec_level);
    try std.testing.expect(hint.request_keyframe);
}

test "allocator-backed forward clone has no leaks" {
    var session = Session(3).init();
    const alice = try ParticipantId.init("alice");
    const bob = try ParticipantId.init("bob");

    try session.join(alice, .voice);
    try session.join(bob, .voice);

    const route = try session.forwardSet(alice, .voice, .{});
    const owned = try route.cloneRecipients(std.testing.allocator);
    defer std.testing.allocator.free(owned);

    try std.testing.expectEqual(@as(usize, 1), owned.len);
    try std.testing.expect(owned[0].eql(&bob));
}

test "applyTomlVideo defaults match historical 4K@60 guards" {
    var doc = try toml.parse(std.testing.allocator, "");
    defer doc.deinit(std.testing.allocator);
    var cfg: VideoConfig = .{};
    applyTomlVideo(&cfg, &doc);
    try std.testing.expectEqual(default_max_layer_width, cfg.max_layer_width);
    try std.testing.expectEqual(default_max_layer_height, cfg.max_layer_height);
    try std.testing.expectEqual(default_max_layer_fps, cfg.max_layer_fps);
    try std.testing.expectEqual(default_receiver_max_fps, cfg.default_receiver_max_fps);
    try std.testing.expectEqual(default_receiver_max_fps, (ReceiverConstraints{ .max_bitrate_kbps = 1, .max_width = 1, .max_height = 1 }).max_fps);
}

test "applyTomlVideo overlays media.video and drives SimulcastLayer guards" {
    const src =
        \\[media.video]
        \\max_layer_width = 1280
        \\max_layer_height = 720
        \\max_layer_fps = 30
        \\default_receiver_max_fps = 30
    ;
    var doc = try toml.parse(std.testing.allocator, src);
    defer doc.deinit(std.testing.allocator);
    var cfg: VideoConfig = .{};
    applyTomlVideo(&cfg, &doc);
    try std.testing.expectEqual(@as(u16, 1280), cfg.max_layer_width);

    // Within the tightened bounds: accepted.
    _ = try SimulcastLayer.initWithConfig(cfg, "h", 900, 1280, 720, 30);
    // Above the tightened geometry / fps: rejected.
    try std.testing.expectError(error.InvalidLayerGeometry, SimulcastLayer.initWithConfig(cfg, "f", 2500, 1920, 1080, 30));
    try std.testing.expectError(error.InvalidLayerFps, SimulcastLayer.initWithConfig(cfg, "x", 900, 1280, 720, 60));
    // The default-config init still accepts 4K@60 (defaults unchanged).
    _ = try SimulcastLayer.init("f", 2500, 3840, 2160, 60);
}

test "applyTomlAbr defaults match historical AbrConfig" {
    var doc = try toml.parse(std.testing.allocator, "");
    defer doc.deinit(std.testing.allocator);
    var cfg: AbrConfig = .{};
    applyTomlAbr(&cfg, &doc);
    const def: AbrConfig = .{};
    try std.testing.expectEqual(def.min_bitrate_kbps, cfg.min_bitrate_kbps);
    try std.testing.expectEqual(def.max_bitrate_kbps, cfg.max_bitrate_kbps);
    try std.testing.expectEqual(def.high_loss_percent, cfg.high_loss_percent);
    try std.testing.expectEqual(def.high_rtt_ms, cfg.high_rtt_ms);
    try std.testing.expectEqual(@as(u16, 20), cfg.high_nack_per_second);
    try std.testing.expectEqual(@as(u32, 60), cfg.congestion_decrease_percent);
    try std.testing.expectEqual(@as(u32, 80), cfg.congestion_utilization_percent);
    try std.testing.expectEqual(@as(u8, 15), cfg.fec_escalate_loss_percent);
    try std.testing.expectEqual(@as(u32, 25), cfg.increase_headroom_percent);
    try std.testing.expectEqual(@as(u32, 115), cfg.increase_step_percent);
    try std.testing.expectEqual(@as(u8, 1), cfg.hold_no_fec_loss_percent);
    try std.testing.expectEqual(@as(u8, 3), cfg.max_fec_level);
}

test "abrHint behavior with defaults is unchanged after lifting" {
    // Congested by NACK rate (>= 20) drives a decrease with FEC level 2.
    const decrease = try abrHint(.{}, .{
        .current_bitrate_kbps = 1000,
        .available_bitrate_kbps = 2000,
        .packet_loss_percent = 0,
        .rtt_ms = 10,
        .nack_per_second = 25,
    });
    try std.testing.expectEqual(AbrAction.decrease, decrease.action);
    try std.testing.expectEqual(@as(u8, 2), decrease.fec_level);
    try std.testing.expectEqual(@as(u32, 600), decrease.target_bitrate_kbps); // 60% of 1000

    // High loss escalates FEC to the max level on decrease.
    const escalate = try abrHint(.{}, .{
        .current_bitrate_kbps = 1000,
        .available_bitrate_kbps = 2000,
        .packet_loss_percent = 20,
        .rtt_ms = 10,
    });
    try std.testing.expectEqual(@as(u8, 3), escalate.fec_level);

    // Ample headroom (> 25%) drives an increase to 115% of current.
    const increase = try abrHint(.{}, .{
        .current_bitrate_kbps = 1000,
        .available_bitrate_kbps = 5000,
        .packet_loss_percent = 0,
        .rtt_ms = 10,
    });
    try std.testing.expectEqual(AbrAction.increase, increase.action);
    try std.testing.expectEqual(@as(u32, 1150), increase.target_bitrate_kbps);
}

test "applyTomlAbr overlays media.abr and changes abrHint thresholds" {
    const src =
        \\[media.abr]
        \\high_nack_per_second = 100
        \\congestion_decrease_percent = 50
        \\increase_step_percent = 200
    ;
    var doc = try toml.parse(std.testing.allocator, src);
    defer doc.deinit(std.testing.allocator);
    var cfg: AbrConfig = .{};
    applyTomlAbr(&cfg, &doc);
    try std.testing.expectEqual(@as(u16, 100), cfg.high_nack_per_second);

    // 25 NACKs/sec no longer congests at the raised threshold, and with ample
    // headroom the stream now increases by the configured 200% step.
    const hint = try abrHint(cfg, .{
        .current_bitrate_kbps = 1000,
        .available_bitrate_kbps = 5000,
        .packet_loss_percent = 0,
        .rtt_ms = 10,
        .nack_per_second = 25,
    });
    try std.testing.expectEqual(AbrAction.increase, hint.action);
    try std.testing.expectEqual(@as(u32, 2000), hint.target_bitrate_kbps);
}

test "active media DTO native session preserves exact roster modes and swap removal" {
    const testing = std.testing;
    const S = Session(4);
    var old = S.init();
    const a = try ParticipantId.init("A");
    const b = try ParticipantId.init("B");
    const c = try ParticipantId.init("C");
    try old.join(a, .voice);
    try old.join(b, .video);
    try old.join(c, .voice);
    try old.join(a, .screen);
    try old.setMuted(a, .video, true); // accepted unjoined-kind state
    try old.setSpeaking(a, .voice, true);
    try old.leaveAll(b);
    const carry = try old.capture();
    var candidate = try S.prepareRestore(&carry);
    try testing.expectEqualDeep(carry, try candidate.capture());
    try testing.expectEqualDeep(try old.forwardSet(a, .voice, .{ .require_speaking = true }), try candidate.forwardSet(a, .voice, .{ .require_speaking = true }));
    try candidate.join(b, .screen);
    try testing.expectEqual(@as(usize, 2), old.count());
    var bad = carry;
    bad.len = 5;
    try testing.expectError(error.InvalidSnapshot, S.prepareRestore(&bad));
    bad = carry;
    bad.participants[1].id = a;
    try testing.expectError(error.InvalidSnapshot, S.prepareRestore(&bad));
    bad = carry;
    bad.participants[0].id.bytes[63] = 1;
    try testing.expectError(error.InvalidSnapshot, S.prepareRestore(&bad));
    bad = carry;
    bad.participants[0].speaking.bits = 8;
    try testing.expectError(error.InvalidSnapshot, S.prepareRestore(&bad));
    bad = carry;
    bad.participants[3].joined.bits = 1;
    try testing.expectError(error.InvalidSnapshot, S.prepareRestore(&bad));
    try testing.expectEqualDeep(carry, try old.capture());
}
