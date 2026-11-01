// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! UNDERTOW frame layer.
//!
//! This module sits directly above CoilPack's fixed UNDERTOW header codec. It
//! keeps frame handling allocation-free: callers provide complete input slices
//! and output buffers, while transport code owns buffering and I/O.
const std = @import("std");
const coilpack = @import("coilpack.zig");

pub const header_len = coilpack.undertow_header_len;
pub const max_payload_len = std.math.maxInt(u16);
pub const default_hop_count: u8 = 16;
pub const default_credit_window: u32 = 4 * 1024 * 1024;
pub const credit_grant_threshold: u32 = 16 * 1024;

pub const EncodeError = coilpack.EncodeError || error{
    PayloadTooLarge,
    HopExpired,
    UnknownRequiredType,
};

pub const DecodeError = coilpack.DecodeError || error{
    PayloadTooLarge,
    HopExpired,
    UnknownRequiredType,
    TrailingBytes,
};

pub const CreditError = error{
    InsufficientCredit,
    CreditOverflow,
};

pub const FrameBand = enum {
    control,
    sync,
    irc_app,
    capability,
    mooring,
    media,
    unknown,
};

pub const Priority = enum(u3) {
    idle = 0,
    low = 1,
    bulk = 2,
    sync = 3,
    normal = 4,
    high = 5,
    realtime = 6,
    control = 7,
};

pub const CtrlFlag = struct {
    pub const ack: u4 = 0x8;
    pub const fin: u4 = 0x4;
    pub const frag: u4 = 0x2;
    pub const dict: u4 = 0x1;
};

/// Decoded UNDERTOW control byte: flags[7:4], priority[3:1], compression[0].
pub const Ctrl = struct {
    flags: u4 = 0,
    priority: Priority = .normal,
    compressed: bool = false,

    pub fn init(flags: u4, priority: Priority, compressed: bool) Ctrl {
        return .{ .flags = flags, .priority = priority, .compressed = compressed };
    }

    pub fn fromByte(byte: u8) Ctrl {
        return .{
            .flags = @intCast(byte >> 4),
            .priority = @fromBackingInt(@intCast(@as(u3, @intCast((byte >> 1) & 0x07)))),
            .compressed = (byte & 0x01) != 0,
        };
    }

    pub fn toByte(self: Ctrl) u8 {
        return (@as(u8, self.flags) << 4) |
            (@as(u8, @backingInt(self.priority)) << 1) |
            @as(u8, if (self.compressed) 1 else 0);
    }

    pub fn hasFlag(self: Ctrl, flag: u4) bool {
        return (self.flags & flag) != 0;
    }
};

/// UNDERTOW frame types. Unknown extension values can still be represented and
/// classified by their numeric band.
pub const FrameType = enum(u8) {
    hello = 0x01,
    auth = 0x02,
    auth_ok = 0x03,
    auth_fail = 0x04,
    err = 0x05,
    ping = 0x06,
    pong = 0x07,
    disconnect = 0x08,
    credit = 0x09,

    gossip_push = 0x10,
    gossip_pull = 0x11,
    gossip_ack = 0x12,
    ping_req = 0x13,
    ping_req_ack = 0x14,
    concord_delta = 0x20,
    concord_snapshot = 0x21,
    sync_bloom = 0x22,
    sync_merkle = 0x23,
    sync_want = 0x24,

    privmsg = 0x80,
    notice = 0x81,
    join = 0x82,
    part = 0x83,
    kick = 0x84,
    ban = 0x85,
    mode = 0x86,
    topic = 0x87,
    nick = 0x88,
    quit = 0x89,
    whois = 0x8a,
    invite = 0x8b,
    irc_line = 0x8f,

    cap_grant = 0x90,
    cap_revoke = 0x91,

    mooring_handshake = 0xa0,
    mooring_handshake_resp = 0xa1,
    mooring_ratchet = 0xa2,
    mooring_group_key = 0xa3,

    voice_join = 0xb0,
    voice_leave = 0xb1,
    voice_data = 0xb2,
    voice_mute = 0xb3,
    voice_unmute = 0xb4,
    voice_speaking = 0xb5,
    video_join = 0xb6,
    video_leave = 0xb7,
    video_data = 0xb8,
    video_keyreq = 0xb9,
    screen_data = 0xba,
    media_stats = 0xbb,
    media_nack = 0xbc,
    media_bye = 0xbd,
    media_offer = 0xbe,
    media_answer = 0xbf,
    screen_mute = 0xc0,
    screen_unmute = 0xc1,
    voice_kick = 0xc2,
    video_kick = 0xc3,
    channel_info_req = 0xc4,
    channel_info = 0xc5,
    media_ping = 0xc6,
    media_pong = 0xc7,
    channel_msg = 0xc8,
    reaction = 0xc9,
    deafen = 0xca,
    undeafen = 0xcb,
    record_start = 0xcc,
    record_stop = 0xcd,
    voice_activity = 0xce,
    record_req = 0xcf,
    record_ack = 0xd0,
    channel_msg_v2 = 0xd4,
    capacity_warn = 0xd5,
    channel_info_req2 = 0xd6,
    channel_info_resp = 0xd7,
    media_ping2 = 0xd8,
    media_pong2 = 0xd9,
    screen_leave = 0xda,
    spatial_join = 0xdb,
    spatial_move = 0xdc,
    spatial_leave = 0xdd,
    data_open = 0xe0,
    data_close = 0xe1,
    data_msg = 0xe2,
    transcript_on = 0xe3,
    transcript_off = 0xe4,
    transcript_chunk = 0xe5,
    annotation_on = 0xe6,
    annotation_draw = 0xe7,
    annotation_clr = 0xe8,
    raise_hand = 0xe9,
    lower_hand = 0xea,
    lower_hand_all = 0xeb,
    poll_create = 0xec,
    e2e_key_update = 0xed,
    e2e_key_ack = 0xee,
    poll_vote = 0xef,
    poll_close = 0xf0,
    abr_report = 0xf1,
    quality_hint = 0xf2,
    breakout_create = 0xf3,
    breakout_join = 0xf4,
    breakout_leave = 0xf5,
    breakout_close = 0xf6,
    whiteboard_join = 0xf7,
    whiteboard_draw = 0xf8,
    whiteboard_clr = 0xf9,
    simulcast_decl = 0xfa,
    simulcast_sel = 0xfb,
    spotlight = 0xfc,
    follow_me = 0xfd,

    _,

    pub fn fromByte(value: u8) FrameType {
        return @fromBackingInt(@intCast(value));
    }

    pub fn byte(self: FrameType) u8 {
        return @backingInt(self);
    }

    pub fn band(self: FrameType) FrameBand {
        const value = self.byte();
        return switch (value) {
            0x01...0x09 => .control,
            0x10...0x24 => .sync,
            0x80...0x8f => .irc_app,
            0x90...0x91 => .capability,
            0xa0...0xa3 => .mooring,
            0xb0...0xfd => .media,
            else => .unknown,
        };
    }

    pub fn isKnown(self: FrameType) bool {
        return switch (self) {
            .hello,
            .auth,
            .auth_ok,
            .auth_fail,
            .err,
            .ping,
            .pong,
            .disconnect,
            .credit,
            .gossip_push,
            .gossip_pull,
            .gossip_ack,
            .ping_req,
            .ping_req_ack,
            .concord_delta,
            .concord_snapshot,
            .sync_bloom,
            .sync_merkle,
            .sync_want,
            .privmsg,
            .notice,
            .join,
            .part,
            .kick,
            .ban,
            .mode,
            .topic,
            .nick,
            .quit,
            .whois,
            .invite,
            .irc_line,
            .cap_grant,
            .cap_revoke,
            .mooring_handshake,
            .mooring_handshake_resp,
            .mooring_ratchet,
            .mooring_group_key,
            .voice_join,
            .voice_leave,
            .voice_data,
            .voice_mute,
            .voice_unmute,
            .voice_speaking,
            .video_join,
            .video_leave,
            .video_data,
            .video_keyreq,
            .screen_data,
            .media_stats,
            .media_nack,
            .media_bye,
            .media_offer,
            .media_answer,
            .screen_mute,
            .screen_unmute,
            .voice_kick,
            .video_kick,
            .channel_info_req,
            .channel_info,
            .media_ping,
            .media_pong,
            .channel_msg,
            .reaction,
            .deafen,
            .undeafen,
            .record_start,
            .record_stop,
            .voice_activity,
            .record_req,
            .record_ack,
            .channel_msg_v2,
            .capacity_warn,
            .channel_info_req2,
            .channel_info_resp,
            .media_ping2,
            .media_pong2,
            .screen_leave,
            .spatial_join,
            .spatial_move,
            .spatial_leave,
            .data_open,
            .data_close,
            .data_msg,
            .transcript_on,
            .transcript_off,
            .transcript_chunk,
            .annotation_on,
            .annotation_draw,
            .annotation_clr,
            .raise_hand,
            .lower_hand,
            .lower_hand_all,
            .poll_create,
            .e2e_key_update,
            .e2e_key_ack,
            .poll_vote,
            .poll_close,
            .abr_report,
            .quality_hint,
            .breakout_create,
            .breakout_join,
            .breakout_leave,
            .breakout_close,
            .whiteboard_join,
            .whiteboard_draw,
            .whiteboard_clr,
            .simulcast_decl,
            .simulcast_sel,
            .spotlight,
            .follow_me,
            => true,
            _ => false,
        };
    }

    pub fn isControl(self: FrameType) bool {
        return self.band() == .control;
    }

    pub fn isMooring(self: FrameType) bool {
        return self.band() == .mooring;
    }

    pub fn debitsCredit(self: FrameType) bool {
        return !self.isControl() and !self.isMooring();
    }

    pub fn defaultPriority(self: FrameType) Priority {
        return switch (self.band()) {
            .control, .mooring => .control,
            .sync => .sync,
            .irc_app => switch (self) {
                .privmsg, .notice => .high,
                else => .normal,
            },
            .capability => .normal,
            .media => switch (self.byte()) {
                0xb0...0xbf => .realtime,
                0xd4, 0xd5 => .high,
                else => .normal,
            },
            .unknown => .normal,
        };
    }

    pub fn allowedBeforeEstablished(self: FrameType) bool {
        return switch (self) {
            .hello,
            .auth,
            .auth_ok,
            .auth_fail,
            .err,
            .ping,
            .pong,
            .disconnect,
            .credit,
            => true,
            else => self.isMooring(),
        };
    }

    fn isUnknownRequired(self: FrameType) bool {
        return !self.isKnown() and self.band() == .unknown;
    }
};

/// Zero-copy view of one complete UNDERTOW frame.
pub const Frame = struct {
    type: FrameType,
    ctrl: Ctrl,
    stream_id: u24 = 0,
    hop: u8 = default_hop_count,
    payload: []const u8 = "",

    pub fn encode(self: Frame, out: []u8) EncodeError!usize {
        if (self.payload.len > max_payload_len) return error.PayloadTooLarge;
        if (self.hop == 0) return error.HopExpired;
        if (self.type.isUnknownRequired()) return error.UnknownRequiredType;

        const total = header_len + self.payload.len;
        if (out.len < total) return error.BufferTooSmall;

        _ = try coilpack.encodeHeader(out[0..header_len], .{
            .type = self.type.byte(),
            .ctrl = self.ctrl.toByte(),
            .length = @intCast(self.payload.len),
            .stream_id = self.stream_id,
            .hop = self.hop,
        });
        @memcpy(out[header_len..total], self.payload);
        return total;
    }

    pub fn decode(in: []const u8) DecodeError!Frame {
        if (in.len > header_len + max_payload_len) return error.PayloadTooLarge;

        const header = try coilpack.decodeHeader(in);
        const frame_type = FrameType.fromByte(header.type);
        if (frame_type.isUnknownRequired()) return error.UnknownRequiredType;
        if (header.hop == 0) return error.HopExpired;

        const total = header_len + @as(usize, header.length);
        if (in.len < total) return error.Truncated;
        if (in.len != total) return error.TrailingBytes;

        return .{
            .type = frame_type,
            .ctrl = Ctrl.fromByte(header.ctrl),
            .stream_id = header.stream_id,
            .hop = header.hop,
            .payload = in[header_len..total],
        };
    }
};

pub const GateDecision = enum {
    accept,
    drop,
};

pub fn gateFrame(established: bool, frame_type: FrameType) GateDecision {
    if (established or frame_type.allowedBeforeEstablished()) return .accept;
    return .drop;
}

pub fn creditCost(frame: Frame) u32 {
    if (!frame.type.debitsCredit()) return 0;
    // Spec (transport-state.md): credit is charged over the full inner UNDERTOW
    // frame size INCLUDING the 8-byte header, keeping sender/receiver accounting
    // symmetric across peers. Clamp to the wire ceiling first so a hand-built
    // oversize payload cannot truncate via @intCast and under-debit the window.
    const clamped: u32 = @intCast(@min(frame.payload.len, max_payload_len));
    return header_len + clamped;
}

/// Pure UNDERTOW credit-window accountant. Transport code is responsible for
/// serializing returned CREDIT grants and applying received grants.
pub const CreditWindow = struct {
    remote_available: u32 = default_credit_window,
    local_available: u32 = default_credit_window,
    pending_grant: u32 = 0,

    pub fn init() CreditWindow {
        return .{};
    }

    pub fn debitSend(self: *CreditWindow, frame: Frame) CreditError!void {
        const cost = creditCost(frame);
        if (cost > self.remote_available) return error.InsufficientCredit;
        self.remote_available -= cost;
    }

    pub fn applyCredit(self: *CreditWindow, grant: u32) CreditError!void {
        self.remote_available = std.math.add(u32, self.remote_available, grant) catch
            return error.CreditOverflow;
    }

    pub fn debitReceive(self: *CreditWindow, frame: Frame) CreditError!?u32 {
        const cost = creditCost(frame);
        if (cost > self.local_available) return error.InsufficientCredit;
        self.local_available -= cost;

        if (cost == 0) return null;
        self.pending_grant = std.math.add(u32, self.pending_grant, cost) catch
            return error.CreditOverflow;

        if (self.pending_grant >= credit_grant_threshold) {
            return self.flushGrant();
        }
        return null;
    }

    pub fn flushGrant(self: *CreditWindow) ?u32 {
        if (self.pending_grant == 0) return null;

        const grant = self.pending_grant;
        self.pending_grant = 0;
        self.local_available += grant;
        return grant;
    }
};

test "frame encode decode round trip" {
    const frame = Frame{
        .type = .privmsg,
        .ctrl = Ctrl.init(CtrlFlag.fin, .high, true),
        .stream_id = 0x00c0de,
        .hop = 9,
        .payload = "hello mesh",
    };

    var out: [64]u8 = undefined;
    const written = try frame.encode(&out);
    try std.testing.expectEqual(header_len + frame.payload.len, written);

    const decoded = try Frame.decode(out[0..written]);
    try std.testing.expectEqual(frame.type, decoded.type);
    try std.testing.expectEqual(frame.ctrl.toByte(), decoded.ctrl.toByte());
    try std.testing.expect(decoded.ctrl.hasFlag(CtrlFlag.fin));
    try std.testing.expectEqual(frame.stream_id, decoded.stream_id);
    try std.testing.expectEqual(frame.hop, decoded.hop);
    try std.testing.expectEqualSlices(u8, frame.payload, decoded.payload);
}

test "hop zero is dropped" {
    const frame = Frame{ .type = .ping, .ctrl = Ctrl.init(0, .control, false), .hop = 0 };
    var out: [header_len]u8 = undefined;
    try std.testing.expectError(error.HopExpired, frame.encode(&out));

    _ = try coilpack.encodeHeader(&out, .{
        .type = @backingInt(FrameType.ping),
        .ctrl = Ctrl.init(0, .control, false).toByte(),
        .length = 0,
        .stream_id = 0,
        .hop = 0,
    });
    try std.testing.expectError(error.HopExpired, Frame.decode(&out));
}

test "oversize payloads and buffers are rejected" {
    const payload = @as([(max_payload_len + 1)]u8, @splat(0));
    var tiny: [header_len]u8 = undefined;
    try std.testing.expectError(error.PayloadTooLarge, (Frame{
        .type = .privmsg,
        .ctrl = Ctrl.init(0, .normal, false),
        .payload = &payload,
    }).encode(&tiny));

    const small = Frame{ .type = .ping, .ctrl = Ctrl.init(0, .control, false), .payload = "x" };
    try std.testing.expectError(error.BufferTooSmall, small.encode(&tiny));
}

test "band and priority classification" {
    try std.testing.expectEqual(FrameBand.control, FrameType.hello.band());
    try std.testing.expectEqual(FrameBand.sync, FrameType.concord_delta.band());
    try std.testing.expectEqual(FrameBand.irc_app, FrameType.privmsg.band());
    try std.testing.expectEqual(FrameBand.capability, FrameType.cap_grant.band());
    try std.testing.expectEqual(FrameBand.mooring, FrameType.mooring_ratchet.band());
    try std.testing.expectEqual(FrameBand.media, FrameType.voice_data.band());
    try std.testing.expectEqual(FrameBand.media, FrameType.fromByte(0xf5).band());
    try std.testing.expectEqual(FrameBand.unknown, FrameType.fromByte(0xfe).band());

    try std.testing.expectEqual(Priority.control, FrameType.hello.defaultPriority());
    try std.testing.expectEqual(Priority.sync, FrameType.sync_merkle.defaultPriority());
    try std.testing.expectEqual(Priority.high, FrameType.privmsg.defaultPriority());
    try std.testing.expectEqual(Priority.normal, FrameType.cap_grant.defaultPriority());
    try std.testing.expectEqual(Priority.control, FrameType.mooring_handshake.defaultPriority());
    try std.testing.expectEqual(Priority.realtime, FrameType.voice_data.defaultPriority());
}

test "unknown extension frame types are accepted but unknown required types are rejected" {
    const extension_type = FrameType.fromByte(0x1f);
    try std.testing.expect(!extension_type.isKnown());
    try std.testing.expectEqual(FrameBand.sync, extension_type.band());

    var out: [header_len]u8 = undefined;
    const written = try (Frame{
        .type = extension_type,
        .ctrl = Ctrl.init(0, .sync, false),
    }).encode(&out);
    const decoded = try Frame.decode(out[0..written]);
    try std.testing.expectEqual(@as(u8, 0x1f), decoded.type.byte());

    try std.testing.expectError(error.UnknownRequiredType, (Frame{
        .type = FrameType.fromByte(0xfe),
        .ctrl = Ctrl.init(0, .normal, false),
    }).encode(&out));
}

test "credit debit and grant threshold behavior" {
    var window = CreditWindow.init();
    const data = @as([8192]u8, @splat(0xaa));
    const frame = Frame{ .type = .irc_line, .ctrl = Ctrl.init(0, .normal, false), .payload = &data };
    // Credit is charged over the full inner frame (header + payload), per spec.
    const cost = creditCost(frame);

    try window.debitSend(frame);
    try std.testing.expectEqual(default_credit_window - cost, window.remote_available);

    // First receive accumulates below the grant threshold.
    try std.testing.expectEqual(@as(?u32, null), try window.debitReceive(frame));
    try std.testing.expectEqual(default_credit_window - cost, window.local_available);
    try std.testing.expectEqual(cost, window.pending_grant);

    // Second receive crosses the 16 KiB grant threshold and flushes the grant.
    const grant = try window.debitReceive(frame);
    try std.testing.expectEqual(@as(?u32, cost * 2), grant);
    try std.testing.expectEqual(default_credit_window, window.local_available);
    try std.testing.expectEqual(@as(u32, 0), window.pending_grant);

    try window.applyCredit(grant.?);
    try std.testing.expectEqual(default_credit_window - cost + cost * 2, window.remote_available);

    // Control and MOORING frames never debit the window.
    const before = window.remote_available;
    const control = Frame{ .type = .ping, .ctrl = Ctrl.init(0, .control, false), .payload = &data };
    try window.debitSend(control);
    try std.testing.expectEqual(before, window.remote_available);

    const mooring = Frame{ .type = .mooring_ratchet, .ctrl = Ctrl.init(0, .control, false), .payload = &data };
    try window.debitSend(mooring);
    try std.testing.expectEqual(before, window.remote_available);
}

test "pre established gating accepts handshake control mooring ping and credit only" {
    try std.testing.expectEqual(GateDecision.accept, gateFrame(false, .hello));
    try std.testing.expectEqual(GateDecision.accept, gateFrame(false, .auth));
    try std.testing.expectEqual(GateDecision.accept, gateFrame(false, .auth_ok));
    try std.testing.expectEqual(GateDecision.accept, gateFrame(false, .err));
    try std.testing.expectEqual(GateDecision.accept, gateFrame(false, .ping));
    try std.testing.expectEqual(GateDecision.accept, gateFrame(false, .pong));
    try std.testing.expectEqual(GateDecision.accept, gateFrame(false, .credit));
    try std.testing.expectEqual(GateDecision.accept, gateFrame(false, .mooring_handshake));

    try std.testing.expectEqual(GateDecision.drop, gateFrame(false, .privmsg));
    try std.testing.expectEqual(GateDecision.drop, gateFrame(false, .concord_delta));
    try std.testing.expectEqual(GateDecision.drop, gateFrame(false, .cap_grant));
    try std.testing.expectEqual(GateDecision.drop, gateFrame(false, .voice_data));

    try std.testing.expectEqual(GateDecision.accept, gateFrame(true, .voice_data));
}
