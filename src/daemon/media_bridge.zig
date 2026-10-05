// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Media bridge spine — per-channel cross-leg roster + datagram rewrap.
//!
//! A media call can mix participants on two transports: the native leg
//! (cadence_frame over UDP, our CadenceVox/CadenceVis codec) and the WebRTC leg (RTP/SRTP).
//! Within a leg the respective plane already forwards. This module is the spine
//! that lets a frame ingressing on ONE leg reach participants on the OTHER leg —
//! by header-rewrap only, never transcoding. The codec payload is opaque and
//! shared verbatim; only the transport header (cadence container ↔ RTP) changes.
//!
//! `ChannelBridge` holds the call's roster (who is on which leg + their transport
//! identity) and answers `crossTargets(leg)` — the opposite-leg recipients for a
//! frame that arrived on `leg`. The free `*Datagram` helpers do the actual
//! rewrap, reusing `causeway`. The two live pumps (native + WebRTC) will call
//! these to deliver across legs.
//!
//! Pure SFU: this never encodes/decodes/transcodes media. A mixed call still
//! requires a shared codec (`causeway.selectCommon`); rewrap just moves the
//! agreed opaque payload between the two wire framings.
const std = @import("std");
const causeway = @import("../substrate/causeway.zig");
const causeway_session = @import("../substrate/causeway_session.zig");
const ssrc_map_mod = @import("../substrate/ssrc_map.zig");
const cadence_frame = @import("../substrate/cadence_frame.zig");
const native_feedback = @import("../substrate/native_feedback.zig");
const rtcp_translate = @import("../proto/rtcp_translate.zig");
const rtp_profile = @import("../proto/rtp_profile.zig");
const ice = @import("../proto/ice.zig");

pub const Leg = causeway.Leg; // .native | .webrtc
pub const Codec = causeway.Codec;
pub const TransportAddress = ice.TransportAddress;
pub const PtMap = causeway.PtMap;

pub const Error = causeway.Error || cadence_frame.DecodeError || cadence_frame.EncodeError;

const max_id_bytes = 64;
pub const max_member_codecs = 8;
const max_rewrap = 1600; // >= one MTU datagram after header rewrap
const max_feedback_seqs = 64;

/// Sends `bytes` to `target` on some leg's socket. The callback resolves the
/// target's *live* transport address (learned post-OFFER via STUN / first
/// datagram) from the owning plane, rather than trusting a possibly-stale
/// `target.addr`. `ctx` is the caller's context.
pub const SendFn = *const fn (ctx: *anyopaque, target: *const Member, bytes: []const u8) void;

/// Hook the native pump invokes (after its in-leg forward) to also deliver a
/// frame to the channel's WebRTC members. The implementation looks up the
/// channel's `ChannelBridge` and calls `fanoutNativeToWebrtc`.
pub const CrossLegSink = struct {
    ctx: *anyopaque,
    on_native_frame: *const fn (ctx: *anyopaque, channel: []const u8, datagram: []const u8) void,
    on_native_feedback: ?*const fn (ctx: *anyopaque, channel: []const u8, sender_stream_id: u32, feedback: []const u8) bool = null,

    pub fn onNativeFrame(self: CrossLegSink, channel: []const u8, datagram: []const u8) void {
        self.on_native_frame(self.ctx, channel, datagram);
    }

    pub fn onNativeFeedback(self: CrossLegSink, channel: []const u8, sender_stream_id: u32, feedback: []const u8) bool {
        const cb = self.on_native_feedback orelse return false;
        return cb(self.ctx, channel, sender_stream_id, feedback);
    }
};

/// Hook the WebRTC relay invokes (after its in-leg forward) to also deliver an
/// RTP frame to the channel's native members. The implementation looks up the
/// channel's `ChannelBridge` and calls `fanoutWebrtcToNative`.
pub const RtpCrossSink = struct {
    ctx: *anyopaque,
    on_rtp_frame: *const fn (ctx: *anyopaque, channel: []const u8, rtp: []const u8, keyframe_hint: bool) void,
    on_rtcp_feedback: ?*const fn (ctx: *anyopaque, channel: []const u8, rtcp: []const u8) bool = null,

    pub fn onRtpFrame(self: RtpCrossSink, channel: []const u8, rtp: []const u8, keyframe_hint: bool) void {
        self.on_rtp_frame(self.ctx, channel, rtp, keyframe_hint);
    }

    pub fn onRtcpFeedback(self: RtpCrossSink, channel: []const u8, rtcp: []const u8) bool {
        const cb = self.on_rtcp_feedback orelse return false;
        return cb(self.ctx, channel, rtcp);
    }
};

/// The default per-call RTP payload-type map (dynamic PTs for our codecs). Used
/// when a call hasn't negotiated a custom mapping.
pub fn defaultPtMap() PtMap {
    var m = PtMap{};
    m.add(111, .cadencevox); // audio
    m.add(96, .cadencevis); // video
    return m;
}

fn memberStableId(id: []const u8) u64 {
    return std.hash.Wyhash.hash(0, id);
}

fn knownCodec(codec: Codec) bool {
    return switch (codec) {
        .cadencevox, .cadencevis, .raw => true,
        else => false,
    };
}

/// One call participant and the transport identity needed to deliver to it.
pub const Member = struct {
    id_buf: [max_id_bytes]u8 = undefined,
    id_len: u8 = 0,
    leg: Leg,
    addr: TransportAddress = .{},
    /// Native identity (cadence stream + band the egress frame carries).
    stream_id: u32 = 0,
    band_id: u8 = cadence_frame.MEDIA_BAND_FLOOR,
    /// WebRTC identity (RTP SSRC stamped on the egress packet).
    ssrc: u32 = 0,
    /// Participant-advertised codec capabilities. Empty means unknown; the bridge
    /// remains permissive for tests/legacy callers until signaling supplies caps.
    codecs: [max_member_codecs]Codec = undefined,
    codec_count: u8 = 0,

    pub fn id(self: *const Member) []const u8 {
        return self.id_buf[0..self.id_len];
    }

    pub fn setCodecs(self: *Member, codecs: []const Codec) void {
        const n = @min(codecs.len, self.codecs.len);
        @memcpy(self.codecs[0..n], codecs[0..n]);
        self.codec_count = @intCast(n);
    }

    pub fn codecSlice(self: *const Member) []const Codec {
        return self.codecs[0..self.codec_count];
    }
};

pub fn ChannelBridge(comptime max_participants: usize) type {
    return struct {
        const Self = @This();
        pub const RegisterError = error{ Full, BadId };
        pub const SnapshotError = error{InvalidSnapshot};
        const CodecState = enum { unknown, direct, incompatible };

        /// An inline, canonical roster. It borrows no map value, member codec
        /// slice, or socket address. The caller owns publication of a restored
        /// bridge under the same lock used for register/unregister.
        pub const Snapshot = struct {
            pub const MemberRow = struct {
                id_buf: [max_id_bytes]u8 = @splat(0),
                id_len: u8 = 0,
                leg: Leg = .native,
                addr: TransportAddress = .{},
                stream_id: u32 = 0,
                band_id: u8 = cadence_frame.MEDIA_BAND_FLOOR,
                ssrc: u32 = 0,
                codecs: [max_member_codecs]Codec = @splat(.cadencevox),
                codec_count: u8 = 0,

                fn id(self: *const MemberRow) []const u8 {
                    return self.id_buf[0..self.id_len];
                }
            };

            members: [max_participants]MemberRow = @splat(.{}),
            len: usize = 0,
            pt_entries: [8]PtMap.Entry = @splat(.{ .pt = 0, .codec = .cadencevox }),
            pt_len: usize = 0,

            pub fn validate(self: *const Snapshot) SnapshotError!void {
                if (self.len > max_participants or self.pt_len > self.pt_entries.len) return error.InvalidSnapshot;
                for (self.members[0..self.len], 0..) |row, i| {
                    if (row.id_len == 0 or row.id_len > max_id_bytes or row.codec_count > max_member_codecs or row.addr.ip_len > row.addr.ip.len) return error.InvalidSnapshot;
                    for (row.id_buf[row.id_len..]) |byte| if (byte != 0) return error.InvalidSnapshot;
                    for (row.addr.ip[row.addr.ip_len..]) |byte| if (byte != 0) return error.InvalidSnapshot;
                    for (row.codecs[row.codec_count..]) |codec| if (codec != .cadencevox) return error.InvalidSnapshot;
                    for (row.codecs[0..row.codec_count]) |codec| if (!knownCodec(codec)) return error.InvalidSnapshot;
                    for (self.members[0..i]) |prior| {
                        if (std.mem.eql(u8, row.id(), prior.id()) or memberStableId(row.id()) == memberStableId(prior.id())) return error.InvalidSnapshot;
                        if (row.stream_id != 0 and row.stream_id == prior.stream_id) return error.InvalidSnapshot;
                        if (row.ssrc != 0 and row.ssrc == prior.ssrc) return error.InvalidSnapshot;
                    }
                }
                for (self.members[self.len..]) |row| if (!std.meta.eql(row, MemberRow{})) return error.InvalidSnapshot;
                for (self.pt_entries[0..self.pt_len], 0..) |entry, i| {
                    if (!knownCodec(entry.codec)) return error.InvalidSnapshot;
                    for (self.pt_entries[0..i]) |prior| if (entry.pt == prior.pt or entry.codec == prior.codec) return error.InvalidSnapshot;
                }
                for (self.pt_entries[self.pt_len..]) |entry| if (!std.meta.eql(entry, PtMap.Entry{ .pt = 0, .codec = .cadencevox })) return error.InvalidSnapshot;
            }
        };

        members: [max_participants]Member = undefined,
        len: usize = 0,
        ptmap: PtMap = .{},
        session: causeway_session.Session(max_participants) = .{},
        ssrcs: ssrc_map_mod.SsrcMap(max_participants) = .{},
        codec_state: CodecState = .unknown,
        common_codec: ?Codec = null,

        pub fn init() Self {
            return .{ .ptmap = defaultPtMap() };
        }

        pub fn capture(self: *const Self) SnapshotError!Snapshot {
            if (self.len > max_participants or self.ptmap.len > self.ptmap.entries.len) return error.InvalidSnapshot;
            var snapshot: Snapshot = .{ .len = self.len, .pt_len = self.ptmap.len };
            @memcpy(snapshot.pt_entries[0..snapshot.pt_len], self.ptmap.entries[0..snapshot.pt_len]);
            for (self.members[0..self.len], 0..) |member, i| {
                if (member.id_len == 0 or member.id_len > max_id_bytes or member.codec_count > max_member_codecs or member.addr.ip_len > member.addr.ip.len) return error.InvalidSnapshot;
                var row = Snapshot.MemberRow{
                    .id_len = member.id_len,
                    .leg = member.leg,
                    .stream_id = member.stream_id,
                    .band_id = member.band_id,
                    .ssrc = member.ssrc,
                    .codec_count = member.codec_count,
                };
                @memcpy(row.id_buf[0..member.id_len], member.id_buf[0..member.id_len]);
                row.addr.port = member.addr.port;
                row.addr.ip_len = member.addr.ip_len;
                @memcpy(row.addr.ip[0..member.addr.ip_len], member.addr.ip[0..member.addr.ip_len]);
                @memcpy(row.codecs[0..member.codec_count], member.codecs[0..member.codec_count]);
                snapshot.members[i] = row;
            }
            try snapshot.validate();
            const rebuilt = try prepareRestore(&snapshot);
            if (!self.derivedEquals(&rebuilt)) return error.InvalidSnapshot;
            return snapshot;
        }

        /// Prepare only. The returned value is not installed into the server's
        /// channel map and cannot authorize an ingress by itself.
        pub fn prepareRestore(snapshot: *const Snapshot) SnapshotError!Self {
            try snapshot.validate();
            var result = Self.init();
            result.ptmap.len = snapshot.pt_len;
            @memcpy(result.ptmap.entries[0..snapshot.pt_len], snapshot.pt_entries[0..snapshot.pt_len]);
            result.len = snapshot.len;
            for (snapshot.members[0..snapshot.len], 0..) |row, i| {
                var member = Member{
                    .id_buf = @splat(0),
                    .id_len = row.id_len,
                    .leg = row.leg,
                    .addr = row.addr,
                    .stream_id = row.stream_id,
                    .band_id = row.band_id,
                    .ssrc = row.ssrc,
                    .codecs = @splat(.cadencevox),
                    .codec_count = row.codec_count,
                };
                @memcpy(member.id_buf[0..row.id_len], row.id());
                @memcpy(member.codecs[0..row.codec_count], row.codecs[0..row.codec_count]);
                result.members[i] = member;
            }
            result.recomputeCodec();
            return result;
        }

        fn derivedEquals(self: *const Self, other: *const Self) bool {
            if (self.codec_state != other.codec_state or self.common_codec != other.common_codec or
                self.session.len != other.session.len or self.session.codec != other.session.codec or
                self.ssrcs.len != other.ssrcs.len) return false;
            for (self.session.participants[0..self.session.len], other.session.participants[0..other.session.len]) |a, b| {
                if (a.id != b.id or a.leg != b.leg or a.stream_id != b.stream_id or a.ssrc != b.ssrc or
                    a.connected != b.connected or a.codec_count != b.codec_count or
                    !std.mem.eql(Codec, a.codecs[0..a.codec_count], b.codecs[0..b.codec_count])) return false;
            }
            for (self.ssrcs.entries[0..self.ssrcs.len], other.ssrcs.entries[0..other.ssrcs.len]) |a, b| {
                if (!std.meta.eql(a, b)) return false;
            }
            return true;
        }

        fn find(self: *Self, id: []const u8) ?*Member {
            for (self.members[0..self.len]) |*m| {
                if (std.mem.eql(u8, m.id(), id)) return m;
            }
            return null;
        }

        /// Register/update a participant's leg + transport identity.
        pub fn register(self: *Self, id: []const u8, m: Member) RegisterError!void {
            if (id.len == 0 or id.len > max_id_bytes) return error.BadId;
            if (self.find(id)) |existing| {
                var updated = m;
                @memcpy(updated.id_buf[0..id.len], id);
                updated.id_len = @intCast(id.len);
                existing.* = updated;
                self.recomputeCodec();
                return;
            }
            if (self.len >= max_participants) return error.Full;
            var nm = m;
            @memcpy(nm.id_buf[0..id.len], id);
            nm.id_len = @intCast(id.len);
            self.members[self.len] = nm;
            self.len += 1;
            self.recomputeCodec();
        }

        pub fn unregister(self: *Self, id: []const u8) bool {
            for (self.members[0..self.len], 0..) |*mem, i| {
                if (std.mem.eql(u8, mem.id(), id)) {
                    self.members[i] = self.members[self.len - 1];
                    self.len -= 1;
                    self.recomputeCodec();
                    return true;
                }
            }
            return false;
        }

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// Whether this inline cross-leg roster has no participant state that an
        /// in-place exec would discard. ChannelBridge has no internal mutex: the
        /// owner must hold the same lock used for register/unregister while
        /// consulting this allocation-free predicate.
        pub fn upgradeContinuityReady(self: *const Self) bool {
            return self.count() == 0;
        }

        fn recomputeCodec(self: *Self) void {
            self.session = .{};
            self.ssrcs = .{};
            self.common_codec = null;
            if (self.len == 0) {
                self.codec_state = .unknown;
                return;
            }
            for (self.members[0..self.len]) |*m| {
                if (m.codec_count == 0) {
                    self.codec_state = .unknown;
                    return;
                }
                self.session.join(.{
                    .id = memberStableId(m.id()),
                    .leg = m.leg,
                    .codecs = m.codecSlice(),
                    .stream_id = m.stream_id,
                    .ssrc = m.ssrc,
                }) catch return;
                self.ssrcs.bind(m.stream_id, m.ssrc, memberStableId(m.id())) catch return;
            }
            self.common_codec = self.session.codec;
            self.codec_state = if (self.common_codec != null) .direct else .incompatible;
        }

        pub fn transcodeFree(self: *const Self) bool {
            return self.codec_state == .direct;
        }

        fn codecAllowed(self: *const Self, codec: Codec) bool {
            return switch (self.codec_state) {
                .unknown => true,
                .direct => self.common_codec == codec,
                .incompatible => false,
            };
        }

        fn memberByStableId(self: *const Self, id: u64) ?Member {
            for (self.members[0..self.len]) |m| {
                if (memberStableId(m.id()) == id) return m;
            }
            return null;
        }

        fn crossTargetsForParticipant(self: *Self, from_leg: Leg, from_participant: ?u64, out: []Member) usize {
            const other: Leg = if (from_leg == .native) .webrtc else .native;
            if (from_participant) |pid| {
                var egress: [max_participants]causeway_session.Egress = undefined;
                const en = self.session.forwardTargets(pid, &egress);
                var n: usize = 0;
                for (egress[0..en]) |target| {
                    if (target.leg != other) continue;
                    const member = self.memberByStableId(target.id) orelse continue;
                    if (n >= out.len) break;
                    out[n] = member;
                    n += 1;
                }
                return n;
            }
            return self.crossTargets(from_leg, "", out);
        }

        /// Rewrap a native cadence `datagram` ONCE (keeping the source publisher's
        /// stream_id as the RTP ssrc, so receivers can demux) and send the same
        /// RTP packet to each WebRTC member of the call. Header-only; opaque
        /// payload shared verbatim. The `send` callback resolves each target's
        /// live address.
        pub fn fanoutNativeToWebrtc(self: *Self, datagram: []const u8, send_ctx: *anyopaque, send: SendFn) void {
            const view = cadence_frame.decode(datagram) catch return;
            const bf = causeway.fromNative(view);
            if (!self.codecAllowed(bf.codec)) return;
            var targets: [max_participants]Member = undefined;
            const n = self.crossTargetsForParticipant(.native, self.ssrcs.participantForStream(view.stream_id), &targets);
            if (n == 0) return;
            const ssrc = self.ssrcs.ssrcForStream(view.stream_id) orelse view.stream_id;
            var scratch: [max_rewrap]u8 = undefined;
            const rtp = causeway.toRtp(bf, &self.ptmap, ssrc, &scratch) catch return;
            for (targets[0..n]) |*m| send(send_ctx, m, rtp);
        }

        /// Rewrap an `rtp` packet ONCE to a native cadence datagram (keeping the
        /// source ssrc as the native stream_id) and send to each native member.
        /// Used by the WebRTC relay to bridge to native peers.
        pub fn fanoutWebrtcToNative(self: *Self, rtp: []const u8, keyframe_hint: bool, send_ctx: *anyopaque, send: SendFn) void {
            const dh = rtp_profile.decodeHeader(rtp) catch return;
            const bf = causeway.fromRtp(rtp, &self.ptmap, keyframe_hint) catch return;
            if (!self.codecAllowed(bf.codec)) return;
            var targets: [max_participants]Member = undefined;
            const n = self.crossTargetsForParticipant(.webrtc, self.ssrcs.participantForSsrc(dh.header.ssrc), &targets);
            if (n == 0) return;
            const stream_id = self.ssrcs.streamForSsrc(dh.header.ssrc) orelse dh.header.ssrc;
            const nf = causeway.toNative(bf, cadence_frame.MEDIA_BAND_FLOOR, stream_id);
            var scratch: [max_rewrap]u8 = undefined;
            const len = cadence_frame.encode(nf, &scratch) catch return;
            for (targets[0..n]) |*m| send(send_ctx, m, scratch[0..len]);
        }

        /// Translate WebRTC RTCP feedback into native feedback and send it to
        /// the native publisher named by the media SSRC. Returns true only when
        /// the feedback was recognized and delivered cross-leg.
        pub fn fanoutRtcpFeedbackToNative(self: *Self, rtcp: []const u8, send_ctx: *anyopaque, send: SendFn) bool {
            var seqs16: [max_feedback_seqs]u16 = undefined;
            // WebRTC RTCP arrives as a COMPOUND datagram (a leading SR/RR, often an
            // SDES chunk, then the PLI/FIR/NACK) unless rtcp-rsize is negotiated, so
            // walk sub-packets by length rather than reading only offset 0.
            const fb = rtcp_translate.parseCompound(rtcp, &seqs16) catch return false;
            switch (fb) {
                .keyframe_request => |k| {
                    const pid = self.ssrcs.participantForSsrc(k.media_ssrc) orelse return false;
                    var target = self.memberByStableId(pid) orelse return false;
                    if (target.leg != .native) return false;
                    const stream_id = self.ssrcs.streamForSsrc(k.media_ssrc) orelse target.stream_id;
                    var out: [64]u8 = undefined;
                    const msg = native_feedback.encodeKeyframeRequest(stream_id, &out) catch return false;
                    send(send_ctx, &target, msg);
                    return true;
                },
                .nack => |nack| {
                    const pid = self.ssrcs.participantForSsrc(nack.media_ssrc) orelse return false;
                    var target = self.memberByStableId(pid) orelse return false;
                    if (target.leg != .native) return false;
                    if (nack.seqs.len > max_feedback_seqs) return false;
                    const stream_id = self.ssrcs.streamForSsrc(nack.media_ssrc) orelse target.stream_id;
                    var seqs32: [max_feedback_seqs]u32 = undefined;
                    for (nack.seqs, 0..) |seq, i| seqs32[i] = seq;
                    var out: [1 + 4 + 2 + max_feedback_seqs * 4]u8 = undefined;
                    const msg = native_feedback.encodeNack(stream_id, seqs32[0..nack.seqs.len], &out) catch return false;
                    send(send_ctx, &target, msg);
                    return true;
                },
                .other => return false,
            }
        }

        /// Translate authenticated native feedback into RTCP and send it to the
        /// WebRTC publisher named by the native stream id. The authentication
        /// envelope is stripped by `native_media_transport` before this point.
        pub fn fanoutNativeFeedbackToWebrtc(self: *Self, sender_stream_id: u32, feedback: []const u8, send_ctx: *anyopaque, send: SendFn) bool {
            const sender_pid = self.ssrcs.participantForStream(sender_stream_id) orelse return false;
            const sender = self.memberByStableId(sender_pid) orelse return false;
            if (sender.leg != .native) return false;
            const sender_ssrc = self.ssrcs.ssrcForStream(sender_stream_id) orelse sender_stream_id;
            var seqs32: [max_feedback_seqs]u32 = undefined;
            const msg = native_feedback.parse(feedback, &seqs32) catch return false;
            switch (msg) {
                .keyframe_request => |k| {
                    const pid = self.ssrcs.participantForStream(k.stream_id) orelse return false;
                    var target = self.memberByStableId(pid) orelse return false;
                    if (target.leg != .webrtc) return false;
                    const ssrc = self.ssrcs.ssrcForStream(k.stream_id) orelse target.ssrc;
                    var out: [64]u8 = undefined;
                    const rtcp = rtcp_translate.buildKeyframeRequest(sender_ssrc, ssrc, &out) catch return false;
                    send(send_ctx, &target, rtcp);
                    return true;
                },
                .nack => |nack| {
                    const pid = self.ssrcs.participantForStream(nack.stream_id) orelse return false;
                    var target = self.memberByStableId(pid) orelse return false;
                    if (target.leg != .webrtc) return false;
                    if (nack.seqs.len == 0 or nack.seqs.len > max_feedback_seqs) return false;
                    const ssrc = self.ssrcs.ssrcForStream(nack.stream_id) orelse target.ssrc;
                    var seqs16: [max_feedback_seqs]u16 = undefined;
                    for (nack.seqs, 0..) |seq, i| {
                        if (seq > std.math.maxInt(u16)) return false;
                        seqs16[i] = @intCast(seq);
                    }
                    var out: [12 + max_feedback_seqs * 4]u8 = undefined;
                    const rtcp = rtcp_translate.buildNack(sender_ssrc, ssrc, seqs16[0..nack.seqs.len], &out) catch return false;
                    send(send_ctx, &target, rtcp);
                    return true;
                },
                .receiver_report => return false,
            }
        }

        /// Copy into `out` every member on the leg OPPOSITE to `from_leg`,
        /// excluding `from_id` (the publisher). These are the participants the
        /// caller must reach by rewrapping the frame onto the other transport.
        pub fn crossTargets(self: *Self, from_leg: Leg, from_id: []const u8, out: []Member) usize {
            const other: Leg = if (from_leg == .native) .webrtc else .native;
            var n: usize = 0;
            for (self.members[0..self.len]) |m| {
                if (m.leg != other) continue;
                if (std.mem.eql(u8, m.id(), from_id)) continue;
                if (n >= out.len) break;
                out[n] = m;
                n += 1;
            }
            return n;
        }
    };
}

// ---------------------------------------------------------------------------
// Datagram-level rewrap (reuses causeway; payload is borrowed/opaque).
// ---------------------------------------------------------------------------

/// Rewrap a native cadence datagram as an RTP packet for a WebRTC target
/// (`ssrc`). Header-only: the codec payload is copied verbatim. Returns the RTP
/// bytes in `out`.
pub fn nativeDatagramToRtp(datagram: []const u8, map: *const PtMap, ssrc: u32, out: []u8) Error![]const u8 {
    const view = try cadence_frame.decode(datagram);
    const bf = causeway.fromNative(view);
    return causeway.toRtp(bf, map, ssrc, out);
}

/// Rewrap an RTP packet as a native cadence datagram for a native target
/// (`band_id`/`stream_id`). Header-only. Returns the encoded length in `out`.
pub fn rtpToNativeDatagram(
    rtp: []const u8,
    map: *const PtMap,
    band_id: u8,
    stream_id: u32,
    keyframe_hint: bool,
    out: []u8,
) Error!usize {
    const bf = try causeway.fromRtp(rtp, map, keyframe_hint);
    const nf = causeway.toNative(bf, band_id, stream_id);
    return cadence_frame.encode(nf, out);
}

// ---------------------------------------------------------------------------
// Tests (run under the unified build; transitively imports cadence/rtp_profile,
// so not standalone `zig test`-able — expected).
// ---------------------------------------------------------------------------

const testing = std.testing;

fn addr(last: u8, port: u16) TransportAddress {
    return TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, last }, port) catch unreachable;
}

test "crossTargets returns only opposite-leg members, excluding the sender" {
    var br = ChannelBridge(8).init();
    try br.register("alice", .{ .leg = .native, .addr = addr(1, 5000), .stream_id = 100 });
    try br.register("bob", .{ .leg = .native, .addr = addr(2, 5000), .stream_id = 200 });
    try br.register("mob", .{ .leg = .webrtc, .addr = addr(3, 6000), .ssrc = 0xAAAA });
    try br.register("pho", .{ .leg = .webrtc, .addr = addr(4, 6000), .ssrc = 0xBBBB });

    var out: [8]Member = undefined;
    // a native sender reaches the WebRTC members only
    const n = br.crossTargets(.native, "alice", &out);
    try testing.expectEqual(@as(usize, 2), n);
    for (out[0..n]) |m| try testing.expectEqual(Leg.webrtc, m.leg);

    // a WebRTC sender reaches the native members, excluding itself
    const n2 = br.crossTargets(.webrtc, "mob", &out);
    try testing.expectEqual(@as(usize, 2), n2);
    for (out[0..n2]) |m| try testing.expectEqual(Leg.native, m.leg);
}

test "upgrade continuity: ChannelBridge is ready again after its roster empties" {
    var br = ChannelBridge(8).init();
    try testing.expect(br.upgradeContinuityReady());

    try br.register("alice", .{ .leg = .native, .stream_id = 11 });
    try testing.expect(!br.upgradeContinuityReady());

    try testing.expect(br.unregister("alice"));
    try testing.expect(br.upgradeContinuityReady());
}

test "unregister drops a member; register updates in place" {
    var br = ChannelBridge(4).init();
    try br.register("a", .{ .leg = .native, .stream_id = 1 });
    try br.register("a", .{ .leg = .webrtc, .ssrc = 9 }); // update -> same slot
    try testing.expectEqual(@as(usize, 1), br.count());
    try testing.expect(br.find("a").?.leg == .webrtc);
    try testing.expect(br.unregister("a"));
    try testing.expectEqual(@as(usize, 0), br.count());
    try testing.expect(!br.unregister("a"));
}

test "bridge snapshot roundtrip retains roster and rejects duplicate physical identity" {
    const Bridge = ChannelBridge(4);
    var bridge = Bridge.init();
    var native = Member{ .leg = .native, .stream_id = 17, .addr = addr(1, 7000) };
    native.setCodecs(&.{ .cadencevox, .cadencevis });
    var webrtc = Member{ .leg = .webrtc, .ssrc = 91, .addr = addr(2, 7001) };
    webrtc.setCodecs(&.{.cadencevox});
    try bridge.register("alice", native);
    try bridge.register("mobile", webrtc);
    const snapshot = try bridge.capture();
    var restored = try Bridge.prepareRestore(&snapshot);
    try testing.expect(restored.transcodeFree());
    try testing.expectEqual(@as(usize, 2), restored.count());
    try testing.expectEqual(@as(?u32, 91), restored.ssrcs.ssrcForStream(0));
    try testing.expectEqualDeep(snapshot, try restored.capture());
    var corrupt = snapshot;
    corrupt.members[1].id_buf = corrupt.members[0].id_buf;
    corrupt.members[1].id_len = corrupt.members[0].id_len;
    try testing.expectError(error.InvalidSnapshot, Bridge.prepareRestore(&corrupt));
}

test "bridge map relocation preserves owned Causeway codec sets" {
    const Bridge = ChannelBridge(4);
    var bridges = std.AutoHashMap(u32, Bridge).init(testing.allocator);
    defer bridges.deinit();
    var first = Bridge.init();
    var native = Member{ .leg = .native, .stream_id = 17 };
    native.setCodecs(&.{ .cadencevox, .cadencevis });
    var mobile = Member{ .leg = .webrtc, .ssrc = 91 };
    mobile.setCodecs(&.{.cadencevox});
    try first.register("alice", native);
    try first.register("mobile", mobile);
    try bridges.put(1, first);
    for (2..96) |index| try bridges.put(@intCast(index), Bridge.init());
    const moved = bridges.getPtr(1).?;
    try testing.expectEqual(Codec.cadencevox, moved.session.codec.?);
    try testing.expectEqual(Codec.cadencevox, moved.session.participants[0].codecs[0]);
    try testing.expectEqualDeep(try first.capture(), try moved.capture());
    try testing.expect(moved.unregister("mobile"));
    try testing.expectEqual(Codec.cadencevox, moved.session.codec.?);
}

const CountSendCtx = struct {
    count: usize = 0,

    fn send(ctx: *anyopaque, _: *const Member, _: []const u8) void {
        const self: *CountSendCtx = @ptrCast(@alignCast(ctx));
        self.count += 1;
    }
};

const CaptureSendCtx = struct {
    count: usize = 0,
    bytes: [max_rewrap]u8 = undefined,
    len: usize = 0,

    fn send(ctx: *anyopaque, _: *const Member, bytes: []const u8) void {
        const self: *CaptureSendCtx = @ptrCast(@alignCast(ctx));
        self.count += 1;
        self.len = @min(bytes.len, self.bytes.len);
        @memcpy(self.bytes[0..self.len], bytes[0..self.len]);
    }

    fn written(self: *const CaptureSendCtx) []const u8 {
        return self.bytes[0..self.len];
    }
};

const FeedbackCaptureCtx = struct {
    count: usize = 0,
    target_id: [max_id_bytes]u8 = undefined,
    target_len: usize = 0,
    bytes: [max_rewrap]u8 = undefined,
    len: usize = 0,

    fn send(ctx: *anyopaque, member: *const Member, bytes: []const u8) void {
        const self: *FeedbackCaptureCtx = @ptrCast(@alignCast(ctx));
        self.count += 1;
        self.target_len = @min(member.id().len, self.target_id.len);
        @memcpy(self.target_id[0..self.target_len], member.id()[0..self.target_len]);
        self.len = @min(bytes.len, self.bytes.len);
        @memcpy(self.bytes[0..self.len], bytes[0..self.len]);
    }

    fn target(self: *const FeedbackCaptureCtx) []const u8 {
        return self.target_id[0..self.target_len];
    }

    fn written(self: *const FeedbackCaptureCtx) []const u8 {
        return self.bytes[0..self.len];
    }
};

test "fanout gates cross-leg frames on the shared Causeway codec" {
    var br = ChannelBridge(4).init();
    var native = Member{ .leg = .native, .stream_id = 7 };
    native.setCodecs(&.{.cadencevox});
    var webrtc = Member{ .leg = .webrtc, .ssrc = 0xCAFE };
    webrtc.setCodecs(&.{.cadencevis});
    try br.register("alice", native);
    try br.register("mob", webrtc);
    try testing.expect(!br.transcodeFree());

    var src: [128]u8 = undefined;
    const slen = try cadence_frame.encode(.{
        .band_id = cadence_frame.MEDIA_BAND_FLOOR,
        .stream_id = 7,
        .sequence = 1,
        .timestamp = 1,
        .keyframe = false,
        .codec = .cadencevox_audio,
        .payload = "audio",
    }, &src);

    var ctx = CountSendCtx{};
    br.fanoutNativeToWebrtc(src[0..slen], &ctx, CountSendCtx.send);
    try testing.expectEqual(@as(usize, 0), ctx.count);

    webrtc.setCodecs(&.{ .cadencevox, .cadencevis });
    try br.register("mob", webrtc);
    try testing.expect(br.transcodeFree());
    br.fanoutNativeToWebrtc(src[0..slen], &ctx, CountSendCtx.send);
    try testing.expectEqual(@as(usize, 1), ctx.count);
}

test "fanout translates native stream id to RTP ssrc through ssrc_map" {
    var br = ChannelBridge(4).init();
    var native = Member{ .leg = .native, .stream_id = 7, .ssrc = 0xA111_A111 };
    native.setCodecs(&.{.cadencevox});
    var webrtc = Member{ .leg = .webrtc, .stream_id = 80, .ssrc = 0xB222_B222 };
    webrtc.setCodecs(&.{.cadencevox});
    try br.register("alice", native);
    try br.register("mob", webrtc);

    var src: [128]u8 = undefined;
    const slen = try cadence_frame.encode(.{
        .band_id = cadence_frame.MEDIA_BAND_FLOOR,
        .stream_id = 7,
        .sequence = 1,
        .timestamp = 960,
        .keyframe = false,
        .codec = .cadencevox_audio,
        .payload = "audio",
    }, &src);

    var ctx = CaptureSendCtx{};
    br.fanoutNativeToWebrtc(src[0..slen], &ctx, CaptureSendCtx.send);
    try testing.expectEqual(@as(usize, 1), ctx.count);
    const rtp = try rtp_profile.decodeHeader(ctx.written());
    try testing.expectEqual(@as(u32, 0xA111_A111), rtp.header.ssrc);
}

test "fanout translates RTP ssrc to native stream id through ssrc_map" {
    var br = ChannelBridge(4).init();
    var native = Member{ .leg = .native, .stream_id = 7, .ssrc = 0xA111_A111 };
    native.setCodecs(&.{.cadencevox});
    var webrtc = Member{ .leg = .webrtc, .stream_id = 80, .ssrc = 0xB222_B222 };
    webrtc.setCodecs(&.{.cadencevox});
    try br.register("alice", native);
    try br.register("mob", webrtc);

    const bf = causeway.BridgeFrame{
        .codec = .cadencevox,
        .timestamp = 960,
        .sequence = 1,
        .keyframe = false,
        .payload = "audio",
    };
    var rtp_buf: [128]u8 = undefined;
    const rtp = try causeway.toRtp(bf, &br.ptmap, 0xB222_B222, &rtp_buf);

    var ctx = CaptureSendCtx{};
    br.fanoutWebrtcToNative(rtp, false, &ctx, CaptureSendCtx.send);
    try testing.expectEqual(@as(usize, 1), ctx.count);
    const native_frame = try cadence_frame.decode(ctx.written());
    try testing.expectEqual(@as(u32, 80), native_frame.stream_id);
    try testing.expectEqual(cadence_frame.CodecTag.cadencevox_audio, native_frame.codec);
}

test "fanout honors causeway_session connected target policy" {
    var br = ChannelBridge(4).init();
    var native = Member{ .leg = .native, .stream_id = 7, .ssrc = 0xA111_A111 };
    native.setCodecs(&.{.cadencevox});
    var webrtc = Member{ .leg = .webrtc, .stream_id = 80, .ssrc = 0xB222_B222 };
    webrtc.setCodecs(&.{.cadencevox});
    try br.register("alice", native);
    try br.register("mob", webrtc);

    br.session.get(memberStableId("mob")).?.connected = false;

    var src: [128]u8 = undefined;
    const slen = try cadence_frame.encode(.{
        .band_id = cadence_frame.MEDIA_BAND_FLOOR,
        .stream_id = 7,
        .sequence = 1,
        .timestamp = 960,
        .keyframe = false,
        .codec = .cadencevox_audio,
        .payload = "audio",
    }, &src);

    var ctx = CountSendCtx{};
    br.fanoutNativeToWebrtc(src[0..slen], &ctx, CountSendCtx.send);
    try testing.expectEqual(@as(usize, 0), ctx.count);
}

test "feedback translates WebRTC PLI to native keyframe request" {
    var br = ChannelBridge(4).init();
    var native = Member{ .leg = .native, .stream_id = 100, .ssrc = 0xA100 };
    native.setCodecs(&.{.cadencevis});
    var webrtc = Member{ .leg = .webrtc, .stream_id = 200, .ssrc = 0xB200 };
    webrtc.setCodecs(&.{.cadencevis});
    try br.register("alice", native);
    try br.register("mob", webrtc);

    var rtcp_buf: [64]u8 = undefined;
    const pli = try rtcp_translate.buildKeyframeRequest(0xB200, 0xA100, &rtcp_buf);
    var ctx = FeedbackCaptureCtx{};
    try testing.expect(br.fanoutRtcpFeedbackToNative(pli, &ctx, FeedbackCaptureCtx.send));
    try testing.expectEqual(@as(usize, 1), ctx.count);
    try testing.expectEqualStrings("alice", ctx.target());

    var seq_out: [1]u32 = undefined;
    const msg = try native_feedback.parse(ctx.written(), &seq_out);
    switch (msg) {
        .keyframe_request => |k| try testing.expectEqual(@as(u32, 100), k.stream_id),
        else => return error.TestUnexpectedResult,
    }
}

test "RTCP compound feedback (RR then PLI) translates to a native keyframe request" {
    var br = ChannelBridge(4).init();
    var native = Member{ .leg = .native, .stream_id = 100, .ssrc = 0xA100 };
    native.setCodecs(&.{.cadencevis});
    var webrtc = Member{ .leg = .webrtc, .stream_id = 200, .ssrc = 0xB200 };
    webrtc.setCodecs(&.{.cadencevis});
    try br.register("alice", native);
    try br.register("mob", webrtc);

    // The RFC 3550 compound shape a browser sends without rtcp-rsize: a leading
    // Receiver Report, then the PLI. The pre-fix bridge dropped this as `.other`.
    var rr: [8]u8 = undefined;
    rr[0] = 0x80; // V=2, RC=0
    rr[1] = 201; // RR
    std.mem.writeInt(u16, rr[2..4], 1, .big); // 8 bytes = 2 words
    std.mem.writeInt(u32, rr[4..8], 0xB200, .big);

    var pli_buf: [12]u8 = undefined;
    const pli = try rtcp_translate.buildKeyframeRequest(0xB200, 0xA100, &pli_buf);

    var compound: [8 + 12]u8 = undefined;
    @memcpy(compound[0..8], &rr);
    @memcpy(compound[8..], pli);

    var ctx = FeedbackCaptureCtx{};
    try testing.expect(br.fanoutRtcpFeedbackToNative(&compound, &ctx, FeedbackCaptureCtx.send));
    try testing.expectEqualStrings("alice", ctx.target());

    var seq_out: [1]u32 = undefined;
    const msg = try native_feedback.parse(ctx.written(), &seq_out);
    switch (msg) {
        .keyframe_request => |k| try testing.expectEqual(@as(u32, 100), k.stream_id),
        else => return error.TestUnexpectedResult,
    }
}

test "feedback translates WebRTC NACK to native NACK" {
    var br = ChannelBridge(4).init();
    var native = Member{ .leg = .native, .stream_id = 100, .ssrc = 0xA100 };
    native.setCodecs(&.{.cadencevis});
    var webrtc = Member{ .leg = .webrtc, .stream_id = 200, .ssrc = 0xB200 };
    webrtc.setCodecs(&.{.cadencevis});
    try br.register("alice", native);
    try br.register("mob", webrtc);

    var rtcp_buf: [64]u8 = undefined;
    const nack = try rtcp_translate.buildNack(0xB200, 0xA100, &.{ 10, 12 }, &rtcp_buf);
    var ctx = FeedbackCaptureCtx{};
    try testing.expect(br.fanoutRtcpFeedbackToNative(nack, &ctx, FeedbackCaptureCtx.send));

    var seq_out: [4]u32 = undefined;
    const msg = try native_feedback.parse(ctx.written(), &seq_out);
    switch (msg) {
        .nack => |n| {
            try testing.expectEqual(@as(u32, 100), n.stream_id);
            try testing.expectEqualSlices(u32, &.{ 10, 12 }, n.seqs);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "feedback translates authenticated native keyframe request to WebRTC PLI" {
    var br = ChannelBridge(4).init();
    var native = Member{ .leg = .native, .stream_id = 100, .ssrc = 0xA100 };
    native.setCodecs(&.{.cadencevis});
    var webrtc = Member{ .leg = .webrtc, .stream_id = 0xB200, .ssrc = 0xB200 };
    webrtc.setCodecs(&.{.cadencevis});
    try br.register("alice", native);
    try br.register("mob", webrtc);

    var fb_buf: [64]u8 = undefined;
    const fb = try native_feedback.encodeKeyframeRequest(0xB200, &fb_buf);
    var ctx = FeedbackCaptureCtx{};
    try testing.expect(br.fanoutNativeFeedbackToWebrtc(100, fb, &ctx, FeedbackCaptureCtx.send));
    try testing.expectEqualStrings("mob", ctx.target());
    try testing.expectEqual(@as(u32, 0xA100), std.mem.readInt(u32, ctx.written()[4..8], .big));

    var seq_out: [4]u16 = undefined;
    const rtcp = try rtcp_translate.parse(ctx.written(), &seq_out);
    switch (rtcp) {
        .keyframe_request => |k| try testing.expectEqual(@as(u32, 0xB200), k.media_ssrc),
        else => return error.TestUnexpectedResult,
    }
}

test "feedback translates authenticated native NACK to WebRTC NACK" {
    var br = ChannelBridge(4).init();
    var native = Member{ .leg = .native, .stream_id = 100, .ssrc = 0xA100 };
    native.setCodecs(&.{.cadencevis});
    var webrtc = Member{ .leg = .webrtc, .stream_id = 0xB200, .ssrc = 0xB200 };
    webrtc.setCodecs(&.{.cadencevis});
    try br.register("alice", native);
    try br.register("mob", webrtc);

    var fb_buf: [64]u8 = undefined;
    const fb = try native_feedback.encodeNack(0xB200, &.{ 30, 31 }, &fb_buf);
    var ctx = FeedbackCaptureCtx{};
    try testing.expect(br.fanoutNativeFeedbackToWebrtc(100, fb, &ctx, FeedbackCaptureCtx.send));
    try testing.expectEqual(@as(u32, 0xA100), std.mem.readInt(u32, ctx.written()[4..8], .big));

    var seq_out: [4]u16 = undefined;
    const rtcp = try rtcp_translate.parse(ctx.written(), &seq_out);
    switch (rtcp) {
        .nack => |n| {
            try testing.expectEqual(@as(u32, 0xB200), n.media_ssrc);
            try testing.expectEqualSlices(u16, &.{ 30, 31 }, n.seqs);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "feedback rejects native NACK sequences outside RTP range" {
    var br = ChannelBridge(4).init();
    var native = Member{ .leg = .native, .stream_id = 100, .ssrc = 0xA100 };
    native.setCodecs(&.{.cadencevis});
    var webrtc = Member{ .leg = .webrtc, .stream_id = 0xB200, .ssrc = 0xB200 };
    webrtc.setCodecs(&.{.cadencevis});
    try br.register("alice", native);
    try br.register("mob", webrtc);

    var fb_buf: [64]u8 = undefined;
    const fb = try native_feedback.encodeNack(0xB200, &.{std.math.maxInt(u16) + 1}, &fb_buf);
    var ctx = FeedbackCaptureCtx{};
    try testing.expect(!br.fanoutNativeFeedbackToWebrtc(100, fb, &ctx, FeedbackCaptureCtx.send));
    try testing.expectEqual(@as(usize, 0), ctx.count);
}

test "rewrap native datagram -> RTP -> native preserves codec/payload/keyframe" {
    var map = defaultPtMap();

    // Encode an cadencevis (video) native frame.
    var src: [128]u8 = undefined;
    const slen = try cadence_frame.encode(.{
        .band_id = cadence_frame.MEDIA_BAND_FLOOR + 2,
        .stream_id = 7,
        .sequence = 1234,
        .timestamp = 90000,
        .keyframe = true,
        .codec = .cadencevis_video,
        .payload = "video-payload",
    }, &src);

    // Native -> RTP (for a WebRTC peer's ssrc).
    var rtp_buf: [256]u8 = undefined;
    const rtp = try nativeDatagramToRtp(src[0..slen], &map, 0xCAFEBABE, &rtp_buf);

    // RTP -> native (for a native peer's band/stream).
    var back: [256]u8 = undefined;
    const blen = try rtpToNativeDatagram(rtp, &map, cadence_frame.MEDIA_BAND_FLOOR + 2, 7, true, &back);
    const view = try cadence_frame.decode(back[0..blen]);

    try testing.expectEqual(cadence_frame.CodecTag.cadencevis_video, view.codec);
    try testing.expectEqualStrings("video-payload", view.payload);
    try testing.expect(view.keyframe);
    try testing.expectEqual(@as(u32, 1234 & 0xFFFF), view.sequence); // RTP seq is 16-bit
}

test "rewrap rejects an unknown payload type" {
    var empty = PtMap{};
    var src: [64]u8 = undefined;
    const slen = try cadence_frame.encode(.{
        .band_id = cadence_frame.MEDIA_BAND_FLOOR,
        .stream_id = 1,
        .sequence = 1,
        .timestamp = 1,
        .keyframe = false,
        .codec = .cadencevox_audio,
        .payload = "x",
    }, &src);
    var out: [128]u8 = undefined;
    try testing.expectError(error.UnknownPayloadType, nativeDatagramToRtp(src[0..slen], &empty, 1, &out));
}
