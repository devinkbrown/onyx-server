// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Causeway session — per-call bridge state for the pure-SFU media bridge.
//!
//! Tracks each participant's leg (native Undertow vs WebRTC gateway), its
//! supported codecs, and its transport identity (native `stream_id` / WebRTC
//! `ssrc`). It selects the one codec EVERY participant shares (`selectCommon`),
//! which is what lets the SFU forward a single opaque stream to all peers with
//! zero server codec work — the server never encodes/decodes/transcodes. If the
//! participants share no codec the call is not transcode-free as composed
//! (`transcodeFree() == false`); a participant must renegotiate to a shared
//! codec rather than the server bridging it.
const std = @import("std");
const causeway = @import("causeway.zig");

pub const Leg = causeway.Leg;
pub const Codec = causeway.Codec;

pub const Participant = struct {
    id: u64,
    leg: Leg,
    /// The participant's supported codecs (borrowed).
    codecs: []const Codec,
    /// Native media identity (cadence stream).
    stream_id: u32 = 0,
    /// WebRTC media identity (RTP SSRC).
    ssrc: u32 = 0,
    connected: bool = true,
};

/// A session owns the codec set it uses for forwarding decisions. Bridge
/// values live in movable hash-map storage, so retaining a slice into a bridge
/// member would leave a stale pointer after map growth or Helix restoration.
pub const max_participant_codecs: usize = 8;

pub const StoredParticipant = struct {
    id: u64,
    leg: Leg,
    codecs: [max_participant_codecs]Codec = @splat(.cadencevox),
    codec_count: u8 = 0,
    stream_id: u32 = 0,
    ssrc: u32 = 0,
    connected: bool = true,

    fn codecSlice(self: *const StoredParticipant) []const Codec {
        return self.codecs[0..self.codec_count];
    }
};

/// One forward destination for a relayed frame.
pub const Egress = struct {
    id: u64,
    leg: Leg,
    stream_id: u32,
    ssrc: u32,
};

pub fn Session(comptime max_participants: usize) type {
    return struct {
        const Self = @This();
        pub const Error = error{ Full, TooManyCodecs };

        participants: [max_participants]StoredParticipant = undefined,
        len: usize = 0,
        /// The codec common to every participant, or null when none is shared
        /// (the SFU never transcodes, so a null here means the call cannot run as
        /// composed without a participant renegotiating).
        codec: ?Codec = null,

        pub fn join(self: *Self, p: Participant) Error!void {
            if (self.len >= max_participants) return error.Full;
            if (p.codecs.len > max_participant_codecs) return error.TooManyCodecs;
            var owned = StoredParticipant{
                .id = p.id,
                .leg = p.leg,
                .codec_count = @intCast(p.codecs.len),
                .stream_id = p.stream_id,
                .ssrc = p.ssrc,
                .connected = p.connected,
            };
            @memcpy(owned.codecs[0..p.codecs.len], p.codecs);
            self.participants[self.len] = owned;
            self.len += 1;
            self.recompute();
        }

        pub fn leave(self: *Self, id: u64) bool {
            var i: usize = 0;
            while (i < self.len) : (i += 1) {
                if (self.participants[i].id == id) {
                    self.participants[i] = self.participants[self.len - 1];
                    self.len -= 1;
                    self.recompute();
                    return true;
                }
            }
            return false;
        }

        pub fn get(self: *Self, id: u64) ?*StoredParticipant {
            for (self.participants[0..self.len]) |*p| {
                if (p.id == id) return p;
            }
            return null;
        }

        /// Recompute the call's shared codec across all current participants.
        fn recompute(self: *Self) void {
            if (self.len == 0) {
                self.codec = null;
                return;
            }
            var sets: [max_participants][]const Codec = undefined;
            for (self.participants[0..self.len], 0..) |*p, i| sets[i] = p.codecSlice();
            self.codec = causeway.selectCommon(sets[0..self.len]);
        }

        /// Whether the call can be served transcode-free (a shared codec exists).
        pub fn transcodeFree(self: *const Self) bool {
            return self.codec != null;
        }

        /// Fill `out` with the egress leg/identity of every OTHER connected
        /// participant — the SFU forward set for a frame originating at `from_id`.
        pub fn forwardTargets(self: *const Self, from_id: u64, out: []Egress) usize {
            var n: usize = 0;
            for (self.participants[0..self.len]) |p| {
                if (p.id == from_id or !p.connected) continue;
                if (n >= out.len) break;
                out[n] = .{ .id = p.id, .leg = p.leg, .stream_id = p.stream_id, .ssrc = p.ssrc };
                n += 1;
            }
            return n;
        }
    };
}

// ---------------------------------------------------------------------------
// Tests (run under the unified build; this file transitively imports cadence via
// causeway, so it is not standalone `zig test`-able — that's expected).
// ---------------------------------------------------------------------------

const testing = std.testing;

test "session selects the shared codec and forwards to other legs" {
    var s = Session(8){};
    // native client (cadencevox+cadencevis), webrtc/mobile client (cadencevox only) -> cadencevox common
    try s.join(.{ .id = 1, .leg = .native, .codecs = &.{ .cadencevox, .cadencevis }, .stream_id = 100 });
    try s.join(.{ .id = 2, .leg = .webrtc, .codecs = &.{.cadencevox}, .ssrc = 0xAAAA });
    try testing.expect(s.transcodeFree());
    try testing.expectEqual(Codec.cadencevox, s.codec.?);

    var out: [8]Egress = undefined;
    const n = s.forwardTargets(1, &out);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(Leg.webrtc, out[0].leg);
    try testing.expectEqual(@as(u32, 0xAAAA), out[0].ssrc);
}

test "no shared codec => not transcode-free (server never transcodes)" {
    var s = Session(8){};
    try s.join(.{ .id = 1, .leg = .native, .codecs = &.{.cadencevis} }); // video only
    try s.join(.{ .id = 2, .leg = .webrtc, .codecs = &.{.cadencevox} }); // audio only
    try testing.expect(!s.transcodeFree());
    try testing.expect(s.codec == null);
}

test "leave recomputes the shared codec; Full at capacity" {
    var s = Session(2){};
    try s.join(.{ .id = 1, .leg = .native, .codecs = &.{ .cadencevox, .cadencevis } });
    try s.join(.{ .id = 2, .leg = .webrtc, .codecs = &.{.cadencevis} });
    try testing.expectEqual(Codec.cadencevis, s.codec.?);
    try testing.expectError(error.Full, s.join(.{ .id = 3, .leg = .native, .codecs = &.{.cadencevox} }));
    try testing.expect(s.leave(2));
    try testing.expectEqual(Codec.cadencevox, s.codec.?); // only the native client's first shared codec remains
    try testing.expect(!s.leave(99));
}

test "session owns the joined codec set after caller storage changes" {
    var s = Session(3){};
    var codecs = [_]Codec{ .cadencevox, .cadencevis };
    try s.join(.{ .id = 1, .leg = .native, .codecs = &codecs });
    codecs[0] = .raw;
    try s.join(.{ .id = 2, .leg = .webrtc, .codecs = &.{.cadencevox} });
    try testing.expectEqual(Codec.cadencevox, s.codec.?);
    var too_many: [max_participant_codecs + 1]Codec = undefined;
    @memset(&too_many, .cadencevox);
    try testing.expectError(error.TooManyCodecs, s.join(.{ .id = 3, .leg = .native, .codecs = &too_many }));
}
