// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Configured listener identity and cold-restart compatibility policy.

const Config = @import("model.zig").Config;

/// Ports of listeners Helix can carry only when that listener already existed
/// in the predecessor. Zero means the listener is not configured. TLS counts
/// only when `[tls] enabled` is set: the struct default of 6697 is not itself
/// a listener.
pub const ListenerSet = struct {
    irc: u16 = 0,
    tls: u16 = 0,
    ws: u16 = 0,
    webtransport: u16 = 0,
    s2s: u16 = 0,
    media: u16 = 0,
    native_media: u16 = 0,

    pub fn eql(self: ListenerSet, other: ListenerSet) bool {
        return self.irc == other.irc and
            self.tls == other.tls and
            self.ws == other.ws and
            self.webtransport == other.webtransport and
            self.s2s == other.s2s and
            self.media == other.media and
            self.native_media == other.native_media;
    }
};

/// Shared by `--check-config --against` and the UPGRADE command. The operator
/// sees this before SIGUSR2; a later adopt is not how the refusal is discovered.
pub const cold_restart_required_reason: []const u8 = "cold restart required: adding or removing a configured listener has no Helix checkpoint";

pub fn listenerSetFromConfig(cfg: Config) ListenerSet {
    return .{
        .irc = cfg.listen.irc,
        .tls = if (cfg.tls.enabled) cfg.tls.port else 0,
        .ws = cfg.listen.ws,
        .webtransport = cfg.listen.webtransport,
        .s2s = cfg.listen.s2s,
        .media = cfg.listen.media,
        .native_media = cfg.listen.native_media,
    };
}

pub fn listenerChangeError(live: ListenerSet, proposed: ListenerSet) ?[]const u8 {
    if (live.eql(proposed)) return null;
    return cold_restart_required_reason;
}
