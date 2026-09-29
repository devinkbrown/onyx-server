// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! MEDIA command family. `LinuxServer.handleMedia` is the thunk. This file
//! owns the control-plane subcommands. The SFU, datagram relay, and offer
//! path stay on the server.

const std = @import("std");
const account_identity = @import("../proto/account_identity.zig");
const base64url = @import("../proto/base64url.zig");
const client_model = @import("client.zig");
const media_room = @import("media_room.zig");
const world_model = @import("world.zig");
const platform = @import("../substrate/platform.zig");
const undertow_media = @import("../substrate/undertow/media.zig");

/// `MEDIA <JOIN|LEAVE|MUTE|UNMUTE|SPEAKING|ROSTER|E2EE-*> <#chan> [kind] [arg]` —
/// Onyx Server media control plane. Drives the per-channel SFU participant model and
/// emits call state through the MEDIA Event Spine plane. The media bytes flow
/// over the transport substrate, not this control socket. Caller must be a
/// channel member.
pub fn handle(self: anytype, id: anytype, conn: anytype, parsed: anytype) !void {
    const Server = @TypeOf(self.*);
    // TURN has no allocation API and no auth secret. Refuse it before any
    // channel lookup so a secret or a channel name is not treated as a relay.
    if (parsed.param_count >= 1 and std.ascii.eqlIgnoreCase(parsed.paramSlice()[0], "TURN")) {
        try self.failReply(conn, "MEDIA", "TURN_CUT", "TURN relay is not offered");
        return;
    }
    if (parsed.param_count < 2) {
        try self.replyNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"MEDIA"}, "Usage: MEDIA <JOIN|LEAVE|MUTE|UNMUTE|SPEAKING|ROSTER> <#chan> [kind]");
        return;
    }
    const sub = parsed.paramSlice()[0];
    const channel = parsed.paramSlice()[1];
    if (!world_model.isChannelName(channel) or !self.world.channelExists(channel)) {
        try self.replyNumeric(conn, .ERR_NOSUCHCHANNEL, &.{channel}, "No such channel");
        return;
    }
    // QUALITY is readable by a channel member or an oper who is not on the
    // channel. A non-member who is not an oper still gets 442. The check
    // is here, before the membership gate, because that gate would hide
    // the summary from every oper who is not in the channel.
    if (std.ascii.eqlIgnoreCase(sub, "QUALITY")) {
        if (!self.world.isMember(channel, self.worldIdOf(id)) and !conn.session.isOper()) {
            try self.replyNumeric(conn, .ERR_NOTONCHANNEL, &.{channel}, "You're not on that channel");
            return;
        }
        try self.mediaQuality(conn, channel);
        return;
    }
    if (!self.world.isMember(channel, self.worldIdOf(id))) {
        try self.replyNumeric(conn, .ERR_NOTONCHANNEL, &.{channel}, "You're not on that channel");
        return;
    }
    const nick = conn.session.displayName();

    if (std.ascii.eqlIgnoreCase(sub, "ROSTER")) {
        try self.mediaRoster(conn, channel);
        return;
    }
    if (std.ascii.eqlIgnoreCase(sub, "OFFER")) {
        if (conn.session.hasUmode(.media_tx_deny)) {
            try self.failReply(conn, "MEDIA", "TX_DENIED", "Media transmission is disabled for your session");
            return;
        }
        try self.mediaOffer(
            conn,
            channel,
            if (parsed.param_count >= 3) parsed.paramSlice()[2] else "",
            if (parsed.param_count >= 4) parsed.paramSlice()[3..] else &.{},
        );
        return;
    }
    if (std.ascii.eqlIgnoreCase(sub, "ANSWER")) {
        try self.mediaAnswer(
            conn,
            channel,
            if (parsed.param_count >= 3) parsed.paramSlice()[2] else "",
            if (parsed.param_count >= 4) parsed.paramSlice()[3..] else &.{},
        );
        return;
    }
    if (std.ascii.eqlIgnoreCase(sub, "PROFILE")) {
        if (self.media_rooms.profileOf(channel)) |prof|
            try self.mediaNegotiatedReply(conn, channel, "PROFILE", prof.slice(), prof.fec)
        else
            try self.failReply(conn, "MEDIA", "NO_OFFER", "No active call profile for this channel");
        return;
    }
    if (std.ascii.eqlIgnoreCase(sub, "STATS")) {
        try self.mediaStats(conn, channel);
        return;
    }
    if (std.ascii.eqlIgnoreCase(sub, "CONSENT")) {
        if (parsed.param_count < 3) {
            try self.replyNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"MEDIA"}, "Usage: MEDIA CONSENT <#chan> <on|off>");
            return;
        }
        if (!self.media_rooms.isParticipant(channel, nick)) {
            try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before setting consent");
            return;
        }
        const token = parsed.paramSlice()[2];
        const on = std.ascii.eqlIgnoreCase(token, "on") or std.mem.eql(u8, token, "1");
        const off = std.ascii.eqlIgnoreCase(token, "off") or std.mem.eql(u8, token, "0");
        if (!on and !off) {
            try self.failReply(conn, "MEDIA", "BAD_CONSENT", "Consent must be on or off");
            return;
        }
        if (!try self.media_rooms.setConsent(channel, nick, on)) {
            try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before setting consent");
            return;
        }
        if (!on and self.media_rooms.stopRecording(channel)) {
            try self.broadcastMediaEvent(channel, "RECORD", nick, "stopped");
        }
        try self.broadcastMediaEvent(channel, "CONSENT", nick, if (on) "on" else "off");
        return;
    }
    if (std.ascii.eqlIgnoreCase(sub, "RECORD")) {
        if (!self.media_rooms.isParticipant(channel, nick)) {
            try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before recording");
            return;
        }
        if (parsed.param_count >= 3 and std.ascii.eqlIgnoreCase(parsed.paramSlice()[2], "stop")) {
            if (self.media_rooms.stopRecording(channel)) {
                try self.broadcastMediaEvent(channel, "RECORD", nick, "stopped");
            } else {
                try self.sendMediaEventReply(conn, "RECORD", channel, "active=0");
            }
            return;
        }
        if (!self.media_rooms.allConsented(channel)) {
            try self.failReply(conn, "MEDIA", "CONSENT_REQUIRED", "Every current member must consent before recording");
            return;
        }
        if (self.media_rooms.recordingOf(channel)) |rec| {
            if (rec.active) {
                var buf: [96]u8 = undefined;
                const detail = std.fmt.bufPrint(&buf, "active=1 by={s}", .{rec.by()}) catch return;
                try self.sendMediaEventReply(conn, "RECORD", channel, detail);
                return;
            }
        }
        if (!try self.media_rooms.startRecording(channel, nick)) {
            try self.failReply(conn, "MEDIA", "CONSENT_REQUIRED", "Every current member must consent before recording");
            return;
        }
        try self.broadcastMediaEvent(channel, "RECORD", nick, "started");
        try self.sendMediaEventReply(conn, "RECORD", channel, "started");
        return;
    }
    if (std.ascii.eqlIgnoreCase(sub, "LAYER")) {
        // `MEDIA LAYER <#chan> <max_spatial> <max_temporal>` — receiver-driven
        // simulcast: ask the native SFU to forward this receiver only up to
        // the given spatial/temporal layer (e.g. a small screen / slow link
        // requests the base layer). The SFU drops higher layers without ever
        // decoding; keyframes at/below the ceiling always pass.
        if (parsed.param_count < 4) {
            try self.replyNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"MEDIA"}, "Usage: MEDIA LAYER <#chan> <max_spatial> <max_temporal>");
            return;
        }
        if (!self.media_rooms.isParticipant(channel, nick)) {
            try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before setting a layer ceiling");
            return;
        }
        const max_spatial = std.fmt.parseInt(u8, parsed.paramSlice()[2], 10) catch {
            try self.failReply(conn, "MEDIA", "BAD_LAYER", "max_spatial must be 0-255");
            return;
        };
        const max_temporal = std.fmt.parseInt(u3, parsed.paramSlice()[3], 10) catch {
            try self.failReply(conn, "MEDIA", "BAD_LAYER", "max_temporal must be 0-7");
            return;
        };
        self.native_media.setSelection(channel, nick, .{ .max_spatial = max_spatial, .max_temporal = max_temporal });
        _ = self.media_plane.setReceiverSpatial(channel, nick, max_spatial);
        var detail_buf: [64]u8 = undefined;
        const detail = std.fmt.bufPrint(&detail_buf, "spatial<={d} temporal<={d}", .{ max_spatial, max_temporal }) catch return;
        try self.sendMediaEventReply(conn, "LAYER", channel, detail);
        return;
    }
    if (std.ascii.eqlIgnoreCase(sub, "ABR")) {
        // `MEDIA ABR <#chan> <current_kbps> <available_kbps> <loss_pct> <rtt_ms> [nack_per_sec]`
        // applies the existing Undertow ABR hint and simulcast selector to this
        // receiver's native layer ceiling. It is a control-plane hint only; the
        // SFU still forwards opaque codec bytes and never transcodes.
        if (parsed.param_count < 6) {
            try self.replyNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"MEDIA"}, "Usage: MEDIA ABR <#chan> <current_kbps> <available_kbps> <loss_pct> <rtt_ms> [nack_per_sec]");
            return;
        }
        if (!self.media_rooms.isParticipant(channel, nick)) {
            try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before reporting ABR");
            return;
        }
        const current_kbps = std.fmt.parseInt(u32, parsed.paramSlice()[2], 10) catch {
            try self.failReply(conn, "MEDIA", "BAD_ABR", "current_kbps must be a positive integer");
            return;
        };
        const available_kbps = std.fmt.parseInt(u32, parsed.paramSlice()[3], 10) catch {
            try self.failReply(conn, "MEDIA", "BAD_ABR", "available_kbps must be an integer");
            return;
        };
        const loss_pct = std.fmt.parseInt(u8, parsed.paramSlice()[4], 10) catch {
            try self.failReply(conn, "MEDIA", "BAD_ABR", "loss_pct must be 0-100");
            return;
        };
        const rtt_ms = std.fmt.parseInt(u16, parsed.paramSlice()[5], 10) catch {
            try self.failReply(conn, "MEDIA", "BAD_ABR", "rtt_ms must be 0-65535");
            return;
        };
        const nack_per_sec = if (parsed.param_count >= 7)
            std.fmt.parseInt(u16, parsed.paramSlice()[6], 10) catch {
                try self.failReply(conn, "MEDIA", "BAD_ABR", "nack_per_sec must be 0-65535");
                return;
            }
        else
            0;
        const hint = undertow_media.abrHint(.{}, .{
            .current_bitrate_kbps = current_kbps,
            .available_bitrate_kbps = available_kbps,
            .packet_loss_percent = loss_pct,
            .rtt_ms = rtt_ms,
            .nack_per_second = nack_per_sec,
        }) catch {
            try self.failReply(conn, "MEDIA", "BAD_ABR", "Invalid ABR report");
            return;
        };
        const selected = Server.mediaAbrSelection(hint) catch {
            try self.failReply(conn, "MEDIA", "BAD_ABR", "No active simulcast layer");
            return;
        };
        self.native_media.setSelection(channel, nick, .{ .max_spatial = selected.spatial, .max_temporal = @intCast(selected.temporal) });
        _ = self.media_plane.setReceiverSpatial(channel, nick, selected.spatial);
        const stored = self.media_rooms.setQuality(channel, nick, .{
            .loss_pct = loss_pct,
            .rtt_ms = rtt_ms,
            .spatial = selected.spatial,
            .bitrate_kbps = hint.target_bitrate_kbps,
        }) catch {
            try self.failReply(conn, "MEDIA", "BAD_ABR", "Could not store the quality sample");
            return;
        };
        if (!stored) {
            try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before reporting ABR");
            return;
        }
        var detail_buf: [160]u8 = undefined;
        const keyframe = if (hint.request_keyframe) "true" else "false";
        const detail = std.fmt.bufPrint(&detail_buf, "action={s} bitrate={d} fec={d} keyframe={s} spatial<={d} temporal<={d}", .{
            Server.mediaAbrActionName(hint.action),
            hint.target_bitrate_kbps,
            hint.fec_level,
            keyframe,
            selected.spatial,
            selected.temporal,
        }) catch return;
        try self.sendMediaEventReply(conn, "ABR", channel, detail);
        return;
    }
    if (std.ascii.eqlIgnoreCase(sub, "BREAKOUT")) {
        if (parsed.param_count < 3 or parsed.paramSlice()[2].len == 0) {
            try self.replyNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"MEDIA"}, "Usage: MEDIA BREAKOUT <#chan> <room>");
            return;
        }
        // Must already be in the call to move between breakouts.
        if (!self.media_rooms.isParticipant(channel, nick)) {
            try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before choosing a breakout");
            return;
        }
        const bname = parsed.paramSlice()[2];
        self.media_rooms.setBreakout(channel, nick, bname) catch {
            try self.failReply(conn, "MEDIA", "BREAKOUT_FAILED", "Could not set breakout");
            return;
        };
        try self.broadcastMediaEvent(channel, "BREAKOUT", nick, bname);
        return;
    }
    if (std.ascii.eqlIgnoreCase(sub, "POS")) {
        if (parsed.param_count < 4) {
            try self.replyNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"MEDIA"}, "Usage: MEDIA POS <#chan> <x> <y>");
            return;
        }
        if (!self.media_rooms.isParticipant(channel, nick)) {
            try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before setting a position");
            return;
        }
        const x = std.fmt.parseInt(i32, parsed.paramSlice()[2], 10) catch {
            try self.failReply(conn, "MEDIA", "INVALID_POSITION", "x and y must be integers");
            return;
        };
        const y = std.fmt.parseInt(i32, parsed.paramSlice()[3], 10) catch {
            try self.failReply(conn, "MEDIA", "INVALID_POSITION", "x and y must be integers");
            return;
        };
        self.media_rooms.setPosition(channel, nick, .{ .x = x, .y = y }) catch {
            try self.failReply(conn, "MEDIA", "POS_FAILED", "Could not set position");
            return;
        };
        var xy_buf: [32]u8 = undefined;
        const xy = std.fmt.bufPrint(&xy_buf, "{d} {d}", .{ x, y }) catch return;
        try self.broadcastMediaEvent(channel, "POS", nick, xy);
        return;
    }
    if (std.ascii.eqlIgnoreCase(sub, "CAPTION")) {
        if (parsed.param_count < 3 or parsed.paramSlice()[2].len == 0) {
            try self.replyNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"MEDIA"}, "Usage: MEDIA CAPTION <#chan> :<text>");
            return;
        }
        if (!self.media_rooms.isParticipant(channel, nick)) {
            try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before captioning");
            return;
        }
        const text = parsed.paramSlice()[2];
        _ = self.transcript.push(channel, nick, text, platform.realtimeMillis()) catch {}; // retention is best-effort
        // Live fan-out via the MEDIA event plane (text is the trailing detail,
        // so spaces are preserved as the rest of the event body).
        try self.publishMediaEvent("CAPTION", channel, nick, text);
        return;
    }
    if (std.ascii.eqlIgnoreCase(sub, "TRANSCRIPT")) {
        for (self.transcript.recent(channel)) |c| {
            var buf: [Server.reply_scratch_bytes]u8 = undefined;
            const detail = std.fmt.bufPrint(&buf, "{s} :{s}", .{ c.speaker, c.text }) catch continue;
            try self.sendMediaEventReply(conn, "TRANSCRIPT", channel, detail);
        }
        var end_buf: [Server.reply_scratch_bytes]u8 = undefined;
        const end = std.fmt.bufPrint(&end_buf, "count={d}", .{self.transcript.recent(channel).len}) catch return;
        try self.sendMediaEventReply(conn, "TRANSCRIPT-END", channel, end);
        return;
    }
    if (std.ascii.eqlIgnoreCase(sub, "E2EE-HANDSHAKE") or
        std.ascii.eqlIgnoreCase(sub, "E2EE-GROUPKEY"))
    {
        // E2EE signaling is available only to a stable authenticated
        // identity that is currently participating in this channel's call.
        // The outer IRC/TLS session supplies sender authentication; the
        // server only validates framing/authority and relays opaque crypto.
        if (conn.session.account() == null) {
            try self.failReply(conn, "MEDIA", "AUTH_REQUIRED", "Authenticate before exchanging media encryption state");
            return;
        }
        if (self.mediaPhysicalIndex(id, channel, nick) == null or !self.media_rooms.isParticipant(channel, nick)) {
            try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before exchanging media encryption state");
            return;
        }

        if (std.ascii.eqlIgnoreCase(sub, "E2EE-HANDSHAKE")) {
            if (parsed.param_count != 3) {
                try self.failReply(conn, "MEDIA", "BAD_E2EE_HANDSHAKE", "Usage: MEDIA E2EE-HANDSHAKE <#chan> :<base64-signed-v2-envelope>");
                return;
            }
            const attachment = Server.mediaE2eeHandshakeAttachment(parsed.paramSlice()[2]) orelse {
                try self.failReply(conn, "MEDIA", "BAD_E2EE_HANDSHAKE", "Handshake must be a canonical signed-v2 envelope");
                return;
            };
            var envelope: [Server.media_e2ee_handshake_v2_bytes]u8 = undefined;
            std.base64.standard.Decoder.decode(&envelope, parsed.paramSlice()[2]) catch unreachable;
            const identity_public: [account_identity.public_key_len]u8 = envelope[179..211].*;
            if (!self.accountHasMediaIdentityKey(conn.session.account().?, identity_public)) {
                try self.failReply(conn, "MEDIA", "UNENROLLED_E2EE_IDENTITY", "Handshake identity key is not enrolled for this account");
                return;
            }
            if (!Server.mediaE2eeHandshakeSignatureValid(channel, &envelope)) {
                try self.failReply(conn, "MEDIA", "BAD_E2EE_HANDSHAKE", "Handshake signature does not authenticate this channel envelope");
                return;
            }
            // A physical connection owns at most one live crypto attachment.
            // Retire a superseded attachment before announcing its replacement
            // so peers never retain both A and B for this transport. Clear the
            // local binding immediately after the detach publishes: if the new
            // handshake publication then fails, the connection is fail-closed
            // instead of continuing to authorize the already-retired A.
            if (conn.media_e2ee_attachment_bound and !conn.mediaE2eeAttachmentMatches(attachment)) {
                const superseded = conn.media_e2ee_attachment;
                try self.publishMediaE2eeDetach(channel, nick, superseded);
                conn.clearMediaE2eeAttachment();
            }
            var detail_buf: [Server.media_e2ee_max_base64_bytes + 1]u8 = undefined;
            const detail = std.fmt.bufPrint(&detail_buf, ":{s}", .{parsed.paramSlice()[2]}) catch return error.OutputTooSmall;
            try self.publishMediaEvent("E2EE-HANDSHAKE", channel, nick, detail);
            conn.bindMediaE2eeAttachment(attachment);
            return;
        }

        if (std.ascii.eqlIgnoreCase(sub, "E2EE-GROUPKEY")) {
            if (parsed.param_count != 7) {
                try self.failReply(conn, "MEDIA", "BAD_E2EE_GROUPKEY", "Usage: MEDIA E2EE-GROUPKEY <#chan> <sender-attachment> <target-nick> <target-attachment> <group-epoch> :<base64-wrapped-key>");
                return;
            }
            const sender_attachment_token = parsed.paramSlice()[2];
            const target = parsed.paramSlice()[3];
            const target_attachment_token = parsed.paramSlice()[4];
            const epoch = parsed.paramSlice()[5];
            const wrapped = parsed.paramSlice()[6];
            const sender_attachment = Server.mediaE2eeAttachmentToken(sender_attachment_token) orelse {
                try self.failReply(conn, "MEDIA", "BAD_E2EE_SENDER", "Sender attachment must be canonical base64url");
                return;
            };
            if (!conn.mediaE2eeAttachmentMatches(sender_attachment)) {
                try self.failReply(conn, "MEDIA", "BAD_E2EE_SENDER", "Sender attachment does not match this connection's accepted handshake");
                return;
            }
            if (target.len == 0 or target.len > client_model.MAX_NICK_BYTES or
                !self.world.isMemberByNick(channel, target) or
                !self.media_rooms.isParticipant(channel, target))
            {
                try self.failReply(conn, "MEDIA", "BAD_E2EE_TARGET", "Target must be a current participant in this channel's call");
                return;
            }
            _ = Server.mediaE2eeAttachmentToken(target_attachment_token) orelse {
                try self.failReply(conn, "MEDIA", "BAD_E2EE_TARGET", "Target attachment must be canonical base64url");
                return;
            };
            if (!Server.validMediaE2eeEpoch(epoch) or !Server.validMediaE2eeBase64(wrapped, 1, Server.media_e2ee_max_wrapped_key_bytes)) {
                try self.failReply(conn, "MEDIA", "BAD_E2EE_GROUPKEY", "Group epoch and wrapped key must use bounded canonical encodings");
                return;
            }
            var detail_buf: [base64url.encodedLen(Server.media_e2ee_attachment_bytes) * 2 + client_model.MAX_NICK_BYTES + 20 + Server.media_e2ee_max_base64_bytes + 6]u8 = undefined;
            const detail = std.fmt.bufPrint(&detail_buf, "{s} {s} {s} {s} :{s}", .{
                sender_attachment_token,
                target,
                target_attachment_token,
                epoch,
                wrapped,
            }) catch return error.OutputTooSmall;
            try self.publishMediaEvent("E2EE-GROUPKEY", channel, nick, detail);
            return;
        }
    }
    if (std.ascii.eqlIgnoreCase(sub, "QUEUE")) {
        try self.mediaQueue(conn, channel);
        return;
    }
    if (std.ascii.eqlIgnoreCase(sub, "HAND")) {
        if (!self.media_rooms.isParticipant(channel, nick)) {
            try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before raising your hand");
            return;
        }
        const up = parsed.param_count < 3 or // bare HAND raises
            std.ascii.eqlIgnoreCase(parsed.paramSlice()[2], "up") or
            std.ascii.eqlIgnoreCase(parsed.paramSlice()[2], "1");
        self.media_rooms.setHand(channel, nick, up) catch {
            try self.failReply(conn, "MEDIA", "HAND_FAILED", "Could not update hand");
            return;
        };
        try self.broadcastMediaEvent(channel, "HAND", nick, if (up) "up" else "down");
        return;
    }
    if (std.ascii.eqlIgnoreCase(sub, "REACT")) {
        if (parsed.param_count < 3 or parsed.paramSlice()[2].len == 0 or parsed.paramSlice()[2].len > self.config.media_reactions_max_token_bytes) {
            try self.failReply(conn, "MEDIA", "INVALID_REACTION", "Usage: MEDIA REACT <#chan> <reaction>");
            return;
        }
        if (!self.media_rooms.isParticipant(channel, nick)) {
            try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "Join the call before reacting");
            return;
        }
        // Ephemeral: broadcast only, no retention.
        try self.broadcastMediaEvent(channel, "REACT", nick, parsed.paramSlice()[2]);
        return;
    }
    // E2EE-DETACH is synthesized only by the server when one physical
    // attachment retires while the shared nick remains in the call. A
    // client must never be able to forge another device's crypto teardown.
    if (std.ascii.eqlIgnoreCase(sub, "E2EE-DETACH")) {
        try self.failReply(conn, "MEDIA", "INVALID_SUBCOMMAND", "E2EE-DETACH is server-originated");
        return;
    }
    if (std.ascii.eqlIgnoreCase(sub, "LEAVE")) {
        const removal = try self.retireMediaPhysicalChannel(id, conn, channel, nick);
        if (removal == .absent) try self.noticeTo(conn, "MEDIA: you are not in this call");
        return;
    }

    // The remaining subcommands all take a kind (default voice).
    const kind_tok = if (parsed.param_count >= 3) parsed.paramSlice()[2] else "voice";
    const kind = media_room.parseKind(kind_tok) orelse {
        try self.failReply(conn, "MEDIA", "INVALID_KIND", "Kind must be voice, video, or screen");
        return;
    };
    const kname = media_room.kindName(kind);

    if (std.ascii.eqlIgnoreCase(sub, "JOIN")) {
        if (conn.session.hasUmode(.media_tx_deny)) {
            try self.failReply(conn, "MEDIA", "TX_DENIED", "Media transmission is disabled for your session");
            return;
        }
        const physical = self.addMediaPhysicalAttachment(id, channel, nick, kind) catch {
            try self.failReply(conn, "MEDIA", "JOIN_FAILED", "Could not join the call");
            return;
        };
        if (!physical.changed) return;
        self.media_rooms.join(channel, nick, kind) catch {
            self.rollbackMediaPhysicalKind(id, channel, nick, kind);
            try self.failReply(conn, "MEDIA", "JOIN_FAILED", "Could not join the call");
            return;
        };
        if (self.media_physical_attachments.items.len == 1 or physical.first_kind) conn.clearMediaE2eeAttachment();
        if (physical.first_kind) try self.broadcastMediaEvent(channel, "JOIN", nick, kname);
        if (physical.first_kind) {
            if (self.media_rooms.recordingOf(channel)) |rec| {
                if (rec.active and !self.media_rooms.hasConsent(channel, nick)) {
                    _ = self.media_rooms.stopRecording(channel);
                    try self.broadcastMediaEvent(channel, "RECORD", nick, "stopped");
                    try self.sendMediaEventReply(conn, "RECORD", channel, "stopped");
                }
            }
        }
        // Era 3 C3: closed-tab call invite for co-channel members not yet in media.
        if (physical.first_kind) self.webpushNotifyCallInvite(channel, nick);
        // WS media plane: bind this connection to the call and hand it the
        // per-stream MAC key so its browser can authenticate each datagram.
        if (self.config.ws_media_relay and conn.ws != null) {
            conn.setMediaCall(channel, nick);
            if (conn.mediaCallChannel() != null) self.issueMediaMacKey(conn, channel, nick);
        }
    } else if (std.ascii.eqlIgnoreCase(sub, "MUTE")) {
        if (self.media_rooms.setMuted(channel, nick, kind, true))
            try self.broadcastMediaEvent(channel, "MUTE", nick, kname)
        else
            try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "You are not publishing that kind");
    } else if (std.ascii.eqlIgnoreCase(sub, "UNMUTE")) {
        if (conn.session.hasUmode(.media_tx_deny)) {
            try self.failReply(conn, "MEDIA", "TX_DENIED", "Media transmission is disabled for your session");
            return;
        }
        if (self.media_rooms.setMuted(channel, nick, kind, false))
            try self.broadcastMediaEvent(channel, "UNMUTE", nick, kname)
        else
            try self.failReply(conn, "MEDIA", "NOT_IN_CALL", "You are not publishing that kind");
    } else if (std.ascii.eqlIgnoreCase(sub, "SPEAKING")) {
        // The speaking queue is visible to the room. This command does not
        // read it: a member who is not at the head still publishes. The
        // sender's client enforces "you are not at the head."
        if (conn.session.hasUmode(.media_tx_deny)) {
            try self.failReply(conn, "MEDIA", "TX_DENIED", "Media transmission is disabled for your session");
            return;
        }
        const on = parsed.param_count >= 4 and
            (std.ascii.eqlIgnoreCase(parsed.paramSlice()[3], "on") or std.ascii.eqlIgnoreCase(parsed.paramSlice()[3], "1"));
        if (self.media_rooms.setSpeaking(channel, nick, kind, on))
            try self.broadcastMediaEvent(channel, if (on) "SPEAKING" else "SILENT", nick, kname)
        else
            try self.failReply(conn, "MEDIA", "NOT_PUBLISHING", "You are not publishing that kind");
    } else {
        try self.failReply(conn, "MEDIA", "INVALID_SUBCOMMAND", "Use JOIN, LEAVE, MUTE, UNMUTE, SPEAKING, BREAKOUT, POS, HAND, QUEUE, REACT, CAPTION, TRANSCRIPT, CONSENT, RECORD, QUALITY, E2EE-HANDSHAKE, E2EE-GROUPKEY, or ROSTER");
    }
}
