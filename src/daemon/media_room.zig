// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-channel media rooms — the daemon-side manager that maps an IRC channel
//! to a Undertow media Session (the SFU participant model). This is the control
//! plane only: it tracks who is in a call and what they publish (voice/video/
//! screen) plus mute/speaking state. The media bytes themselves flow over the
//! transport substrate, not through here.
//!
//! Rooms are created on first join and pruned when empty. Each room is heap-
//! allocated (the Session value is large) and keyed by an owned channel name.
const std = @import("std");
const media = @import("../substrate/undertow/media.zig");
const toml = @import("../proto/toml.zig");
const sdp = @import("../proto/sdp.zig");

pub const default_max_participants: usize = 64;
pub const max_participants: usize = 256;
pub const Room = media.Session(max_participants);
pub const MediaKind = media.MediaKind;
pub const Participant = media.Participant;

/// Runtime-tunable media-room bounds. `max_participants` is still the inline
/// `Session(N)` ceiling; `Config.max_participants` is a runtime cap below it.
pub const Config = struct {
    max_participants: usize = default_max_participants,
    max_breakout_bytes: usize = max_breakout_bytes,
};

/// Overlay media room keys from a parsed TOML document onto `cfg`.
pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
    if (doc.getUint("media.max_participants")) |v| {
        // Clamp into [1, max_participants]. Zero would brick every call (join
        // rejects when count() >= cap, and count() >= 0 is always true); a value
        // above the inline Session(N) ceiling is meaningless and only masks the
        // real limit that join enforces.
        cfg.max_participants = std.math.clamp(@as(usize, @intCast(v)), 1, max_participants);
    }
    if (doc.getUint("media.sfu.max_breakout_label_bytes")) |v| cfg.max_breakout_bytes = @intCast(v);
}

pub const Error = std.mem.Allocator.Error || media.SessionError;

/// Parse a media-kind token (case-insensitive). "audio" is an alias for voice.
pub fn parseKind(name: []const u8) ?MediaKind {
    if (std.ascii.eqlIgnoreCase(name, "voice") or std.ascii.eqlIgnoreCase(name, "audio")) return .voice;
    if (std.ascii.eqlIgnoreCase(name, "video")) return .video;
    if (std.ascii.eqlIgnoreCase(name, "screen")) return .screen;
    return null;
}

pub fn kindName(kind: MediaKind) []const u8 {
    return switch (kind) {
        .voice => "voice",
        .video => "video",
        .screen => "screen",
    };
}

pub const default_breakout = "main";
pub const max_breakout_bytes: usize = 32;

/// 2D position in a call's spatial-audio plane (arbitrary integer units; clients
/// scale/normalize). Default is the origin (centered / non-spatial).
pub const Position = struct { x: i32 = 0, y: i32 = 0 };

/// The stored record of a call recording. `by` is the member who started it.
pub const Recording = struct {
    by_buf: [64]u8 = undefined,
    by_len: usize = 0,
    active: bool = false,

    pub fn by(self: *const Recording) []const u8 {
        return self.by_buf[0..self.by_len];
    }
};

/// One member's latest call-quality sample. No keys, credentials, or payloads.
pub const Quality = struct {
    loss_pct: u8 = 0,
    rtt_ms: u16 = 0,
    spatial: u8 = 0,
    bitrate_kbps: u32 = 0,
};

/// Max distinct codecs a negotiated call profile retains.
pub const max_profile_codecs: usize = 4;

/// The codec/FEC set agreed for a channel's call, established by `MEDIA OFFER`
/// and used as the baseline a later `MEDIA ANSWER` negotiates against. Stored
/// fully inline (all scalar fields) so no per-call heap allocation is needed.
pub const CallProfile = struct {
    codecs: [max_profile_codecs]sdp.Codec = undefined,
    codec_count: u8 = 0,
    fec: sdp.Fec = .{ .scheme = .none, .redundancy = 0 },

    /// Borrowed view of the negotiated codecs.
    pub fn slice(self: *const CallProfile) []const sdp.Codec {
        return self.codecs[0..self.codec_count];
    }
};

pub const MediaRooms = struct {
    allocator: std.mem.Allocator,
    config: Config,
    rooms: std.StringHashMap(*Room),
    /// Optional breakout (sub-room) label per participant, keyed by the composite
    /// "channel\x00participant". Absent = the default "main" breakout. Kept in a
    /// flat map so the substrate Session participant model stays untouched.
    breakouts: std.StringHashMap([]u8),
    /// Optional spatial-audio position per participant (same composite key).
    /// Absent = origin. Value is inline (no per-entry allocation).
    positions: std.StringHashMap(Position),
    /// Raised-hand set (same composite key). Presence of the key = hand raised.
    hands: std.StringHashMap(void),
    /// Negotiated codec/FEC profile per channel (the call's agreed media set),
    /// keyed by an owned channel name. Established by `MEDIA OFFER`; consulted by
    /// `MEDIA ANSWER`. Cleared when the call ends.
    profiles: std.StringHashMap(CallProfile),
    /// Per-(channel,participant) advertised codec/FEC capability set. This is
    /// distinct from the channel profile: it records what each participant can
    /// receive so Causeway can keep the call transcode-free.
    participant_profiles: std.StringHashMap(CallProfile),
    /// Visible consent bits, keyed by "channel\x00participant". Absent means
    /// the member has not consented. There is no hidden-recorder flag.
    consents: std.StringHashMap(void),
    /// One oper-visible recording note per channel. The room announcement is
    /// the existence signal; this row is the stored artifact. It is not a
    /// media capture and it is cleared when the call ends.
    recordings: std.StringHashMap(Recording),
    /// Last congestion sample per member. Loss, RTT, chosen spatial layer,
    /// and target bitrate only — never keying material.
    qualities: std.StringHashMap(Quality),

    pub fn init(allocator: std.mem.Allocator) MediaRooms {
        return initConfig(allocator, .{});
    }

    pub fn initConfig(allocator: std.mem.Allocator, config: Config) MediaRooms {
        return .{
            .allocator = allocator,
            .config = config,
            .rooms = std.StringHashMap(*Room).init(allocator),
            .breakouts = std.StringHashMap([]u8).init(allocator),
            .positions = std.StringHashMap(Position).init(allocator),
            .hands = std.StringHashMap(void).init(allocator),
            .profiles = std.StringHashMap(CallProfile).init(allocator),
            .participant_profiles = std.StringHashMap(CallProfile).init(allocator),
            .consents = std.StringHashMap(void).init(allocator),
            .recordings = std.StringHashMap(Recording).init(allocator),
            .qualities = std.StringHashMap(Quality).init(allocator),
        };
    }

    pub fn deinit(self: *MediaRooms) void {
        var it = self.rooms.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.rooms.deinit();
        var bit = self.breakouts.iterator();
        while (bit.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.breakouts.deinit();
        var pit = self.positions.keyIterator();
        while (pit.next()) |key| self.allocator.free(key.*);
        self.positions.deinit();
        var hit = self.hands.keyIterator();
        while (hit.next()) |key| self.allocator.free(key.*);
        self.hands.deinit();
        var fit = self.profiles.keyIterator();
        while (fit.next()) |key| self.allocator.free(key.*);
        self.profiles.deinit();
        var cit = self.participant_profiles.keyIterator();
        while (cit.next()) |key| self.allocator.free(key.*);
        self.participant_profiles.deinit();
        var consent_it = self.consents.keyIterator();
        while (consent_it.next()) |key| self.allocator.free(key.*);
        self.consents.deinit();
        var rec_it = self.recordings.keyIterator();
        while (rec_it.next()) |key| self.allocator.free(key.*);
        self.recordings.deinit();
        var qit = self.qualities.keyIterator();
        while (qit.next()) |key| self.allocator.free(key.*);
        self.qualities.deinit();
        self.* = undefined;
    }

    /// Whether this control plane has no live media state that would be lost by
    /// an in-place exec. The server serializes every MediaRooms mutation under
    /// its World write lock; callers must hold that same ownership boundary
    /// while consulting this allocation-free snapshot.
    ///
    /// Check every map, not only `rooms`: an interrupted signaling operation can
    /// leave a negotiated profile or participant metadata before a Room exists.
    /// Treating any such state as idle would make the upgrade gate fail open.
    pub fn upgradeContinuityReady(self: *const MediaRooms) bool {
        return self.rooms.count() == 0 and
            self.breakouts.count() == 0 and
            self.positions.count() == 0 and
            self.hands.count() == 0 and
            self.profiles.count() == 0 and
            self.participant_profiles.count() == 0 and
            self.consents.count() == 0 and
            self.recordings.count() == 0 and
            self.qualities.count() == 0;
    }

    /// Build the "channel\x00participant" composite key into `buf`.
    fn breakoutKey(buf: []u8, channel: []const u8, pid: []const u8) ?[]const u8 {
        if (channel.len + 1 + pid.len > buf.len) return null;
        @memcpy(buf[0..channel.len], channel);
        buf[channel.len] = 0;
        @memcpy(buf[channel.len + 1 ..][0..pid.len], pid);
        return buf[0 .. channel.len + 1 + pid.len];
    }

    /// Assign `pid` in `channel` to breakout `name` (truncated to the cap).
    pub fn setBreakout(self: *MediaRooms, channel: []const u8, pid: []const u8, name: []const u8) Error!void {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return;
        const trimmed = name[0..@min(name.len, self.config.max_breakout_bytes)];
        const owned_value = try self.allocator.dupe(u8, trimmed);
        var value_stored = false;
        errdefer if (!value_stored) self.allocator.free(owned_value);
        const gop = try self.breakouts.getOrPut(k);
        if (!gop.found_existing) {
            gop.key_ptr.* = self.allocator.dupe(u8, k) catch |e| {
                _ = self.breakouts.remove(k);
                return e;
            };
        } else {
            self.allocator.free(gop.value_ptr.*);
        }
        gop.value_ptr.* = owned_value;
        value_stored = true;
    }

    /// The breakout `pid` is in within `channel` (default "main").
    pub fn breakoutOf(self: *const MediaRooms, channel: []const u8, pid: []const u8) []const u8 {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return default_breakout;
        return self.breakouts.get(k) orelse default_breakout;
    }

    fn clearBreakout(self: *MediaRooms, channel: []const u8, pid: []const u8) void {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return;
        if (self.breakouts.fetchRemove(k)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
        }
    }

    /// Set `pid`'s spatial-audio position within `channel`.
    pub fn setPosition(self: *MediaRooms, channel: []const u8, pid: []const u8, pos: Position) Error!void {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return;
        const gop = try self.positions.getOrPut(k);
        if (!gop.found_existing) {
            gop.key_ptr.* = self.allocator.dupe(u8, k) catch |e| {
                _ = self.positions.remove(k);
                return e;
            };
        }
        gop.value_ptr.* = pos;
    }

    /// `pid`'s position within `channel` (origin if unset).
    pub fn positionOf(self: *const MediaRooms, channel: []const u8, pid: []const u8) Position {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return .{};
        return self.positions.get(k) orelse .{};
    }

    fn clearPosition(self: *MediaRooms, channel: []const u8, pid: []const u8) void {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return;
        if (self.positions.fetchRemove(k)) |kv| self.allocator.free(kv.key);
    }

    /// Raise or lower `pid`'s hand in `channel`.
    pub fn setHand(self: *MediaRooms, channel: []const u8, pid: []const u8, raised: bool) Error!void {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return;
        if (raised) {
            const gop = try self.hands.getOrPut(k);
            if (!gop.found_existing) {
                gop.key_ptr.* = self.allocator.dupe(u8, k) catch |e| {
                    _ = self.hands.remove(k);
                    return e;
                };
            }
        } else self.clearHand(channel, pid);
    }

    /// Whether `pid`'s hand is raised in `channel`.
    pub fn handRaised(self: *const MediaRooms, channel: []const u8, pid: []const u8) bool {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return false;
        return self.hands.contains(k);
    }

    fn clearHand(self: *MediaRooms, channel: []const u8, pid: []const u8) void {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return;
        if (self.hands.fetchRemove(k)) |kv| self.allocator.free(kv.key);
    }

    /// The room for `channel`, or null when no call is active there.
    pub fn room(self: *MediaRooms, channel: []const u8) ?*Room {
        return self.rooms.get(channel);
    }

    /// Record the call's negotiated codec/FEC set for `channel` (overwrites any
    /// prior profile). `codecs` is copied inline (truncated to the cap).
    pub fn setProfile(self: *MediaRooms, channel: []const u8, codecs: []const sdp.Codec, fec: sdp.Fec) Error!void {
        self.clearParticipantProfilesForChannel(channel);
        var prof = CallProfile{ .fec = fec };
        const n = @min(codecs.len, max_profile_codecs);
        @memcpy(prof.codecs[0..n], codecs[0..n]);
        prof.codec_count = @intCast(n);
        const gop = try self.profiles.getOrPut(channel);
        if (!gop.found_existing) {
            gop.key_ptr.* = self.allocator.dupe(u8, channel) catch |e| {
                _ = self.profiles.remove(channel);
                return e;
            };
        }
        gop.value_ptr.* = prof;
    }

    /// The negotiated profile for `channel`, or null when none has been set.
    pub fn profileOf(self: *const MediaRooms, channel: []const u8) ?CallProfile {
        return self.profiles.get(channel);
    }

    fn clearProfile(self: *MediaRooms, channel: []const u8) void {
        if (self.profiles.fetchRemove(channel)) |kv| self.allocator.free(kv.key);
    }

    /// Record one participant's advertised codec/FEC capabilities for `channel`.
    /// `codecs` is copied inline (truncated to the cap).
    pub fn setParticipantProfile(self: *MediaRooms, channel: []const u8, pid: []const u8, codecs: []const sdp.Codec, fec: sdp.Fec) Error!void {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return;
        var prof = CallProfile{ .fec = fec };
        const n = @min(codecs.len, max_profile_codecs);
        @memcpy(prof.codecs[0..n], codecs[0..n]);
        prof.codec_count = @intCast(n);
        const gop = try self.participant_profiles.getOrPut(k);
        if (!gop.found_existing) {
            gop.key_ptr.* = self.allocator.dupe(u8, k) catch |e| {
                _ = self.participant_profiles.remove(k);
                return e;
            };
        }
        gop.value_ptr.* = prof;
    }

    /// One participant's advertised codec/FEC capabilities, if known.
    pub fn participantProfileOf(self: *const MediaRooms, channel: []const u8, pid: []const u8) ?CallProfile {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return null;
        return self.participant_profiles.get(k);
    }

    pub fn clearParticipantProfile(self: *MediaRooms, channel: []const u8, pid: []const u8) void {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return;
        if (self.participant_profiles.fetchRemove(k)) |kv| self.allocator.free(kv.key);
    }

    fn clearParticipantProfilesForChannel(self: *MediaRooms, channel: []const u8) void {
        var victims: [max_participants][]const u8 = undefined;
        var n: usize = 0;
        var it = self.participant_profiles.keyIterator();
        while (it.next()) |key| {
            const k = key.*;
            if (k.len <= channel.len or k[channel.len] != 0) continue;
            if (!std.mem.eql(u8, k[0..channel.len], channel)) continue;
            if (n >= victims.len) break;
            victims[n] = k;
            n += 1;
        }
        for (victims[0..n]) |key| {
            _ = self.participant_profiles.remove(key);
            self.allocator.free(key);
        }
    }

    /// Participant `pid` joins `channel`'s call publishing `kind` (creating the
    /// room on first join).
    pub fn join(self: *MediaRooms, channel: []const u8, pid: []const u8, kind: MediaKind) Error!void {
        const id = try media.ParticipantId.init(pid);
        const r = try self.ensure(channel);
        if (r.participant(id) == null and r.count() >= @min(self.config.max_participants, max_participants))
            return error.ParticipantCapacityExceeded;
        try r.join(id, kind);
    }

    /// Participant `pid` leaves `channel` entirely (all kinds). Returns true if
    /// they were present; prunes the room when it empties.
    pub fn leaveAll(self: *MediaRooms, channel: []const u8, pid: []const u8) bool {
        const entry = self.rooms.getEntry(channel) orelse return false;
        const id = media.ParticipantId.init(pid) catch return false;
        entry.value_ptr.*.leaveAll(id) catch return false;
        self.clearBreakout(channel, pid);
        self.clearPosition(channel, pid);
        self.clearHand(channel, pid);
        self.clearParticipantProfile(channel, pid);
        self.clearConsent(channel, pid);
        self.clearQuality(channel, pid);
        if (entry.value_ptr.*.count() == 0) self.dropRoom(entry);
        return true;
    }

    pub fn setMuted(self: *MediaRooms, channel: []const u8, pid: []const u8, kind: MediaKind, muted: bool) bool {
        const r = self.rooms.get(channel) orelse return false;
        const id = media.ParticipantId.init(pid) catch return false;
        r.setMuted(id, kind, muted) catch return false;
        return true;
    }

    pub fn setSpeaking(self: *MediaRooms, channel: []const u8, pid: []const u8, kind: MediaKind, speaking: bool) bool {
        const r = self.rooms.get(channel) orelse return false;
        const id = media.ParticipantId.init(pid) catch return false;
        r.setSpeaking(id, kind, speaking) catch return false;
        return true;
    }

    /// Borrowed participant slice for `channel` (empty if no room).
    pub fn roster(self: *MediaRooms, channel: []const u8) []const Participant {
        const r = self.rooms.get(channel) orelse return &.{};
        return r.participants[0..r.len];
    }

    /// Whether `pid` is currently in `channel`'s call.
    pub fn isParticipant(self: *MediaRooms, channel: []const u8, pid: []const u8) bool {
        const r = self.rooms.get(channel) orelse return false;
        const id = media.ParticipantId.init(pid) catch return false;
        return r.participant(id) != null;
    }

    /// Set the visible consent bit. False when `pid` is not in the call.
    pub fn setConsent(self: *MediaRooms, channel: []const u8, pid: []const u8, on: bool) Error!bool {
        if (!self.isParticipant(channel, pid)) return false;
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return false;
        if (on) {
            const gop = try self.consents.getOrPut(k);
            if (!gop.found_existing) {
                gop.key_ptr.* = self.allocator.dupe(u8, k) catch |e| {
                    _ = self.consents.remove(k);
                    return e;
                };
            }
        } else self.clearConsent(channel, pid);
        return true;
    }

    pub fn hasConsent(self: *const MediaRooms, channel: []const u8, pid: []const u8) bool {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return false;
        return self.consents.contains(k);
    }

    fn clearConsent(self: *MediaRooms, channel: []const u8, pid: []const u8) void {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return;
        if (self.consents.fetchRemove(k)) |kv| self.allocator.free(kv.key);
    }

    /// True only when the call has at least one member and every member has
    /// the consent bit set.
    pub fn allConsented(self: *MediaRooms, channel: []const u8) bool {
        const rows = self.roster(channel);
        if (rows.len == 0) return false;
        for (rows) |p| {
            if (!self.hasConsent(channel, p.id.slice())) return false;
        }
        return true;
    }

    pub fn recordingOf(self: *const MediaRooms, channel: []const u8) ?Recording {
        return self.recordings.get(channel);
    }

    /// Start the room recording. False when consent is not unanimous or a
    /// recording is already active. The note is the stored artifact.
    pub fn startRecording(self: *MediaRooms, channel: []const u8, by_nick: []const u8) Error!bool {
        if (!self.allConsented(channel)) return false;
        if (self.recordings.get(channel)) |existing| {
            if (existing.active) return false;
        }
        var note = Recording{ .active = true };
        const n = @min(by_nick.len, note.by_buf.len);
        @memcpy(note.by_buf[0..n], by_nick[0..n]);
        note.by_len = n;
        const gop = try self.recordings.getOrPut(channel);
        if (!gop.found_existing) {
            gop.key_ptr.* = self.allocator.dupe(u8, channel) catch |e| {
                _ = self.recordings.remove(channel);
                return e;
            };
        }
        gop.value_ptr.* = note;
        return true;
    }

    /// Stop an active recording. False when none is active.
    pub fn stopRecording(self: *MediaRooms, channel: []const u8) bool {
        const note = self.recordings.getPtr(channel) orelse return false;
        if (!note.active) return false;
        note.active = false;
        return true;
    }

    fn clearRecording(self: *MediaRooms, channel: []const u8) void {
        if (self.recordings.fetchRemove(channel)) |kv| self.allocator.free(kv.key);
    }

    /// Remember this member's latest quality sample. False when they are not
    /// in the call. The sample has no key material.
    pub fn setQuality(self: *MediaRooms, channel: []const u8, pid: []const u8, sample: Quality) Error!bool {
        if (!self.isParticipant(channel, pid)) return false;
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return false;
        const gop = try self.qualities.getOrPut(k);
        if (!gop.found_existing) {
            gop.key_ptr.* = self.allocator.dupe(u8, k) catch |e| {
                _ = self.qualities.remove(k);
                return e;
            };
        }
        gop.value_ptr.* = sample;
        return true;
    }

    pub fn qualityOf(self: *const MediaRooms, channel: []const u8, pid: []const u8) ?Quality {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return null;
        return self.qualities.get(k);
    }

    fn clearQuality(self: *MediaRooms, channel: []const u8, pid: []const u8) void {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return;
        if (self.qualities.fetchRemove(k)) |kv| self.allocator.free(kv.key);
    }

    fn ensure(self: *MediaRooms, channel: []const u8) Error!*Room {
        if (self.rooms.get(channel)) |r| return r;
        const r = try self.allocator.create(Room);
        errdefer self.allocator.destroy(r);
        r.* = Room.init();
        const owned = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned);
        try self.rooms.putNoClobber(owned, r);
        return r;
    }

    fn dropRoom(self: *MediaRooms, entry: std.StringHashMap(*Room).Entry) void {
        const key = entry.key_ptr.*;
        const r = entry.value_ptr.*;
        self.clearProfile(key);
        self.clearRecording(key);
        self.rooms.removeByPtr(entry.key_ptr);
        self.allocator.free(key);
        self.allocator.destroy(r);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "join/roster/leave lifecycle prunes empty rooms" {
    var m = MediaRooms.init(testing.allocator);
    defer m.deinit();
    try testing.expect(m.room("#c") == null);
    try m.join("#c", "alice", .voice);
    try m.join("#c", "bob", .voice);
    try testing.expectEqual(@as(usize, 2), m.roster("#c").len);
    try testing.expect(m.leaveAll("#c", "alice"));
    try testing.expectEqual(@as(usize, 1), m.roster("#c").len);
    try testing.expect(m.leaveAll("#c", "bob"));
    try testing.expect(m.room("#c") == null); // pruned
}

test "upgrade continuity: MediaRooms is ready only without live control state" {
    var m = MediaRooms.init(testing.allocator);
    defer m.deinit();

    try testing.expect(m.upgradeContinuityReady());

    try m.join("#c", "alice", .voice);
    const codecs = [_]sdp.Codec{.{ .tag = .cadencevox, .clock_rate = 48000, .params = 0 }};
    try m.setProfile("#c", &codecs, .{ .scheme = .none, .redundancy = 0 });
    try m.setParticipantProfile("#c", "alice", &codecs, .{ .scheme = .none, .redundancy = 0 });
    try m.setBreakout("#c", "alice", "stage");
    try m.setPosition("#c", "alice", .{ .x = 4, .y = -2 });
    try m.setHand("#c", "alice", true);
    try testing.expect(!m.upgradeContinuityReady());

    try testing.expect(m.leaveAll("#c", "alice"));
    try testing.expect(m.upgradeContinuityReady());
}

test "call profile persists then clears when the call ends" {
    var m = MediaRooms.init(testing.allocator);
    defer m.deinit();
    try testing.expect(m.profileOf("#c") == null);
    try m.join("#c", "alice", .voice);
    const codecs = [_]sdp.Codec{.{ .tag = .cadencevox, .clock_rate = 48000, .params = 0 }};
    try m.setProfile("#c", &codecs, .{ .scheme = .rs_block, .redundancy = 1 });
    const prof = m.profileOf("#c").?;
    try testing.expectEqual(@as(usize, 1), prof.slice().len);
    try testing.expectEqual(sdp.CodecTag.cadencevox, prof.slice()[0].tag);
    try testing.expectEqual(sdp.FecScheme.rs_block, prof.fec.scheme);
    // reassigning overwrites in place (no leak)
    const codecs2 = [_]sdp.Codec{ .{ .tag = .cadencevox, .clock_rate = 48000, .params = 0 }, .{ .tag = .cadencevis, .clock_rate = 90000, .params = 0 } };
    try m.setProfile("#c", &codecs2, .{ .scheme = .none, .redundancy = 0 });
    try testing.expectEqual(@as(usize, 2), m.profileOf("#c").?.slice().len);
    try testing.expect(m.leaveAll("#c", "alice"));
    try testing.expect(m.profileOf("#c") == null); // cleared with the room
}

test "participant codec profile stores and clears on leave" {
    var m = MediaRooms.init(testing.allocator);
    defer m.deinit();
    try m.join("#c", "alice", .voice);
    const codecs = [_]sdp.Codec{
        .{ .tag = .cadencevox, .clock_rate = 48000, .params = 0 },
        .{ .tag = .cadencevis, .clock_rate = 90000, .params = 0 },
    };
    try m.setParticipantProfile("#c", "alice", &codecs, .{ .scheme = .rs_block, .redundancy = 1 });
    const prof = m.participantProfileOf("#c", "alice").?;
    try testing.expectEqual(@as(usize, 2), prof.slice().len);
    try testing.expectEqual(sdp.CodecTag.cadencevox, prof.slice()[0].tag);
    try testing.expectEqual(sdp.FecScheme.rs_block, prof.fec.scheme);
    try testing.expect(m.leaveAll("#c", "alice"));
    try testing.expect(m.participantProfileOf("#c", "alice") == null);
}

test "mute and speaking state track per kind" {
    var m = MediaRooms.init(testing.allocator);
    defer m.deinit();
    try m.join("#c", "alice", .voice);
    try testing.expect(m.setSpeaking("#c", "alice", .voice, true));
    const p = m.room("#c").?.participant(media.ParticipantId.init("alice") catch unreachable).?;
    try testing.expect(p.speaking.contains(.voice));
    try testing.expect(m.setMuted("#c", "alice", .voice, true));
    // muting clears speaking
    const p2 = m.room("#c").?.participant(media.ParticipantId.init("alice") catch unreachable).?;
    try testing.expect(p2.muted.contains(.voice));
    try testing.expect(!p2.speaking.contains(.voice));
}

test "breakout assignment defaults to main and clears on leave" {
    var m = MediaRooms.init(testing.allocator);
    defer m.deinit();
    try m.join("#c", "alice", .voice);
    try testing.expectEqualStrings("main", m.breakoutOf("#c", "alice"));
    try m.setBreakout("#c", "alice", "design");
    try testing.expectEqualStrings("design", m.breakoutOf("#c", "alice"));
    try m.setBreakout("#c", "alice", "ops"); // reassign frees the old value
    try testing.expectEqualStrings("ops", m.breakoutOf("#c", "alice"));
    try testing.expect(m.leaveAll("#c", "alice"));
    try testing.expectEqualStrings("main", m.breakoutOf("#c", "alice")); // cleared
}

test "GAP-V4 recording starts only when every member consented" {
    var m = MediaRooms.init(testing.allocator);
    defer m.deinit();
    try m.join("#c", "alice", .voice);
    try m.join("#c", "bob", .voice);
    try testing.expect(!m.allConsented("#c"));
    try testing.expect(!try m.startRecording("#c", "alice"));
    try testing.expect(try m.setConsent("#c", "alice", true));
    try testing.expect(!m.allConsented("#c"));
    try testing.expect(try m.setConsent("#c", "bob", true));
    try testing.expect(m.allConsented("#c"));
    try testing.expect(try m.startRecording("#c", "alice"));
    const started = m.recordingOf("#c").?;
    try testing.expect(started.active);
    try testing.expectEqualStrings("alice", started.by());

    try m.join("#c", "carol", .voice);
    try testing.expect(!m.hasConsent("#c", "carol"));
    try testing.expect(m.stopRecording("#c"));
    try testing.expect(!m.recordingOf("#c").?.active);

    try testing.expect(try m.setConsent("#c", "carol", true));
    try testing.expect(try m.startRecording("#c", "carol"));
    try testing.expect(try m.setConsent("#c", "bob", false));
    try testing.expect(!m.allConsented("#c"));
    try testing.expect(m.stopRecording("#c"));
    try testing.expect(m.leaveAll("#c", "alice"));
    try testing.expect(m.leaveAll("#c", "bob"));
    try testing.expect(m.leaveAll("#c", "carol"));
    try testing.expect(m.recordingOf("#c") == null);
    try testing.expect(m.upgradeContinuityReady());
}

test "GAP-V5 quality sample is per member and clears on leave" {
    var m = MediaRooms.init(testing.allocator);
    defer m.deinit();
    try m.join("#c", "alice", .voice);
    try testing.expect(!try m.setQuality("#c", "outsider", .{ .loss_pct = 9, .rtt_ms = 9, .spatial = 1, .bitrate_kbps = 9 }));
    try testing.expect(try m.setQuality("#c", "alice", .{ .loss_pct = 4, .rtt_ms = 30, .spatial = 1, .bitrate_kbps = 500 }));
    const sample = m.qualityOf("#c", "alice").?;
    try testing.expectEqual(@as(u8, 4), sample.loss_pct);
    try testing.expectEqual(@as(u16, 30), sample.rtt_ms);
    try testing.expectEqual(@as(u8, 1), sample.spatial);
    try testing.expectEqual(@as(u32, 500), sample.bitrate_kbps);
    try testing.expect(!m.upgradeContinuityReady());
    try testing.expect(m.leaveAll("#c", "alice"));
    try testing.expect(m.qualityOf("#c", "alice") == null);
    try testing.expect(m.upgradeContinuityReady());
}

test "spatial position defaults to origin and clears on leave" {
    var m = MediaRooms.init(testing.allocator);
    defer m.deinit();
    try m.join("#c", "alice", .voice);
    try testing.expectEqual(Position{ .x = 0, .y = 0 }, m.positionOf("#c", "alice"));
    try m.setPosition("#c", "alice", .{ .x = -120, .y = 80 });
    try testing.expectEqual(Position{ .x = -120, .y = 80 }, m.positionOf("#c", "alice"));
    try m.setPosition("#c", "alice", .{ .x = 5, .y = 5 }); // overwrite in place
    try testing.expectEqual(Position{ .x = 5, .y = 5 }, m.positionOf("#c", "alice"));
    try testing.expect(m.leaveAll("#c", "alice"));
    try testing.expectEqual(Position{ .x = 0, .y = 0 }, m.positionOf("#c", "alice")); // cleared
}

test "raise-hand toggles and clears on leave" {
    var m = MediaRooms.init(testing.allocator);
    defer m.deinit();
    try m.join("#c", "alice", .voice);
    try testing.expect(!m.handRaised("#c", "alice"));
    try m.setHand("#c", "alice", true);
    try testing.expect(m.handRaised("#c", "alice"));
    try m.setHand("#c", "alice", true); // idempotent
    try testing.expect(m.handRaised("#c", "alice"));
    try m.setHand("#c", "alice", false);
    try testing.expect(!m.handRaised("#c", "alice"));
    try m.setHand("#c", "alice", true);
    try testing.expect(m.leaveAll("#c", "alice"));
    try testing.expect(!m.handRaised("#c", "alice")); // cleared on leave
}

test "parseKind accepts aliases and rejects junk" {
    try testing.expectEqual(MediaKind.voice, parseKind("AUDIO").?);
    try testing.expectEqual(MediaKind.voice, parseKind("voice").?);
    try testing.expectEqual(MediaKind.video, parseKind("Video").?);
    try testing.expectEqual(MediaKind.screen, parseKind("screen").?);
    try testing.expect(parseKind("hologram") == null);
}

test "applyToml defaults match historical constants" {
    var doc = try toml.parse(testing.allocator, "");
    defer doc.deinit(testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try testing.expectEqual(default_max_participants, cfg.max_participants);
    try testing.expectEqual(max_breakout_bytes, cfg.max_breakout_bytes);
}

test "applyToml overlays media participant and sfu breakout caps" {
    const src =
        \\[media]
        \\max_participants = 8
        \\[media.sfu]
        \\max_breakout_label_bytes = 4
    ;
    var doc = try toml.parse(testing.allocator, src);
    defer doc.deinit(testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try testing.expectEqual(@as(usize, 8), cfg.max_participants);
    try testing.expectEqual(@as(usize, 4), cfg.max_breakout_bytes);

    var m = MediaRooms.initConfig(testing.allocator, cfg);
    defer m.deinit();
    try m.join("#c", "alice", .voice);
    try m.setBreakout("#c", "alice", "engineering"); // truncated to 4 bytes
    try testing.expectEqualStrings("engi", m.breakoutOf("#c", "alice"));
}

test "applyToml clamps max_participants into the valid range" {
    // Zero would brick every call: join compares count() >= min(cap, 256),
    // and count() >= 0 is always true, so no participant could ever join.
    // Clamp it up to at least 1.
    {
        var doc = try toml.parse(testing.allocator, "[media]\nmax_participants = 0\n");
        defer doc.deinit(testing.allocator);
        var cfg: Config = .{};
        applyToml(&cfg, &doc);
        try testing.expectEqual(@as(usize, 1), cfg.max_participants);

        var m = MediaRooms.initConfig(testing.allocator, cfg);
        defer m.deinit();
        try m.join("#c", "alice", .voice); // still admits at least one
        try testing.expectEqual(@as(usize, 1), m.roster("#c").len);
    }
    // A value above the inline Session ceiling is meaningless; clamp down to it.
    {
        var doc = try toml.parse(testing.allocator, "[media]\nmax_participants = 100000\n");
        defer doc.deinit(testing.allocator);
        var cfg: Config = .{};
        applyToml(&cfg, &doc);
        try testing.expectEqual(max_participants, cfg.max_participants);
    }
}

test "join refuses new participants at runtime cap" {
    var m = MediaRooms.initConfig(testing.allocator, .{ .max_participants = 2 });
    defer m.deinit();
    try m.join("#c", "alice", .voice);
    try m.join("#c", "bob", .voice);
    try testing.expectError(error.ParticipantCapacityExceeded, m.join("#c", "carol", .voice));
    try m.join("#c", "alice", .video);
    try testing.expectEqual(@as(usize, 2), m.roster("#c").len);
}
