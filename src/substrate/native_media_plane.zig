// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native media plane — the Undertow-side SFU forwarding core, transport-neutral.
//!
//! Composes the existing native pieces into one forward decision: the
//! `undertow.media.Session` roster (who publishes/receives) + per-receiver
//! simulcast layer selection (`cadence_layer.shouldForward`). It answers "for an
//! inbound native cadence frame from X, which participants should receive it,
//! after dropping layers above each receiver's selection?" — and the server
//! forwards the SAME opaque frame bytes to them. NO encode/decode/transcode: a
//! receiver either gets the frame verbatim or it is dropped for being a higher
//! layer than it asked for.
//!
//! Transport-neutral: it commits to no socket. The live daemon drives it over
//! whatever native datagram transport (adaptive_transport/CoilPack) carries the frames — the
//! plane only makes the forwarding decision.
const std = @import("std");
const media = @import("undertow/media.zig");
const cadence_layer = @import("cadence_layer.zig");

pub const ParticipantId = media.ParticipantId;
pub const MediaKind = media.MediaKind;

/// Per-receiver simulcast ceiling (default = receive everything).
pub const Selection = struct {
    max_spatial: u8 = 255,
    max_temporal: u3 = 7,
};

pub fn NativeMediaPlane(comptime max_participants: usize) type {
    return struct {
        const Self = @This();
        pub const Error = media.SessionError;

        session: media.Session(max_participants),
        sel_ids: [max_participants]ParticipantId = undefined,
        sel_vals: [max_participants]Selection = undefined,
        sel_len: usize = 0,

        pub fn init() Self {
            return .{ .session = media.Session(max_participants).init() };
        }

        pub fn join(self: *Self, id: ParticipantId, kind: MediaKind) Error!void {
            try self.session.join(id, kind);
        }
        pub fn leave(self: *Self, id: ParticipantId, kind: MediaKind) Error!void {
            try self.session.leave(id, kind);
        }
        pub fn count(self: *const Self) usize {
            return self.session.count();
        }

        /// Set (or update) a receiver's simulcast ceiling.
        pub fn setSelection(self: *Self, id: ParticipantId, sel: Selection) void {
            for (self.sel_ids[0..self.sel_len], 0..) |existing, i| {
                if (existing.eql(&id)) {
                    self.sel_vals[i] = sel;
                    return;
                }
            }
            if (self.sel_len < self.sel_ids.len) {
                self.sel_ids[self.sel_len] = id;
                self.sel_vals[self.sel_len] = sel;
                self.sel_len += 1;
            }
        }

        pub fn selectionOf(self: *const Self, id: ParticipantId) Selection {
            return self.selectionFor(id);
        }

        fn selectionFor(self: *const Self, id: ParticipantId) Selection {
            for (self.sel_ids[0..self.sel_len], 0..) |existing, i| {
                if (existing.eql(&id)) return self.sel_vals[i];
            }
            return .{}; // default: receive all layers
        }

        /// Compute the recipients for one inbound frame from `source_id`,
        /// dropping receivers whose layer ceiling excludes this frame's layer.
        /// The same opaque frame is forwarded to each returned recipient.
        pub fn forward(
            self: *const Self,
            source_id: ParticipantId,
            kind: MediaKind,
            frame_spatial: u8,
            frame_temporal: u3,
            keyframe: bool,
            out: []ParticipantId,
        ) usize {
            const fs = self.session.forwardSet(source_id, kind, .{}) catch return 0;
            const info = cadence_layer.LayerInfo{
                .spatial = frame_spatial,
                .temporal = frame_temporal,
                .keyframe = keyframe,
                .discardable = false,
            };
            var n: usize = 0;
            for (fs.recipients[0..fs.len]) |rid| {
                const sel = self.selectionFor(rid);
                if (!cadence_layer.shouldForward(info, sel.max_spatial, sel.max_temporal)) continue;
                if (n >= out.len) break;
                out[n] = rid;
                n += 1;
            }
            return n;
        }
    };
}

// ---------------------------------------------------------------------------
// Tests (run under the unified build; transitively imports cadence via the
// undertow media module, so not standalone `zig test`-able — expected).
// ---------------------------------------------------------------------------

const testing = std.testing;

fn pid(s: []const u8) ParticipantId {
    return ParticipantId.init(s) catch unreachable;
}

test "forward returns other receivers for a base-layer frame" {
    var plane = NativeMediaPlane(8).init();
    try plane.join(pid("alice"), .voice);
    try plane.join(pid("bob"), .voice);
    try plane.join(pid("carol"), .voice);

    var out: [8]ParticipantId = undefined;
    const n = plane.forward(pid("alice"), .voice, 0, 0, false, &out);
    try testing.expectEqual(@as(usize, 2), n); // bob + carol, not alice
}

test "layer selection drops higher layers but always keeps keyframes" {
    var plane = NativeMediaPlane(8).init();
    try plane.join(pid("src"), .video);
    try plane.join(pid("lowbw"), .video);
    // lowbw only wants spatial 0, temporal 0
    plane.setSelection(pid("lowbw"), .{ .max_spatial = 0, .max_temporal = 0 });

    var out: [8]ParticipantId = undefined;
    // a high spatial-layer non-keyframe is dropped for lowbw
    try testing.expectEqual(@as(usize, 0), plane.forward(pid("src"), .video, 2, 1, false, &out));
    // the base layer is delivered
    try testing.expectEqual(@as(usize, 1), plane.forward(pid("src"), .video, 0, 0, false, &out));
    // a keyframe at/below the selected spatial layer is always delivered
    try testing.expectEqual(@as(usize, 1), plane.forward(pid("src"), .video, 0, 3, true, &out));
}

test "leave removes a participant from the forward set" {
    var plane = NativeMediaPlane(8).init();
    try plane.join(pid("a"), .voice);
    try plane.join(pid("b"), .voice);
    var out: [8]ParticipantId = undefined;
    try testing.expectEqual(@as(usize, 1), plane.forward(pid("a"), .voice, 0, 0, false, &out));
    try plane.leave(pid("b"), .voice);
    try testing.expectEqual(@as(usize, 0), plane.forward(pid("a"), .voice, 0, 0, false, &out));
}
