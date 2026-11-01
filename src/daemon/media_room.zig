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
const routing = @import("../substrate/media_routing.zig");

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
pub const PreparedError = Error || routing.Error || error{ InvalidSnapshot, InvalidProfile };
pub const PhysicalProfileKey = routing.PhysicalProfileKey;
pub const PhysicalMemberKey = struct { call: routing.CallId, client: routing.ClientId };
pub const PhysicalMember = struct { display: media.ParticipantId, kind_bits: u8 };
const PhysicalMemberMap = std.AutoHashMap(PhysicalMemberKey, PhysicalMember);
const ChannelKeyContext = struct {
    pub fn hash(_: ChannelKeyContext, key: []const u8) u64 {
        var h = std.hash.Wyhash.init(0);
        for (key) |byte| {
            const folded = std.ascii.toLower(byte);
            h.update(std.mem.asBytes(&folded));
        }
        return h.final();
    }
    pub fn eql(_: ChannelKeyContext, a: []const u8, b: []const u8) bool {
        return std.ascii.eqlIgnoreCase(a, b);
    }
};
/// Channel spelling is display storage; only ASCII A-Z is folded for lookup.
fn ChannelMap(comptime T: type) type {
    return std.HashMap([]const u8, T, ChannelKeyContext, std.hash_map.default_max_load_percentage);
}
/// Composite metadata preserves the exact participant suffix after the FIRST
/// NUL. Its channel prefix has the same ASCII identity as every room map.
const ParticipantKeyContext = struct {
    pub fn hash(_: ParticipantKeyContext, key: []const u8) u64 {
        const divider = std.mem.indexOfScalar(u8, key, 0) orelse key.len;
        var h = std.hash.Wyhash.init(0);
        for (key[0..divider]) |byte| {
            const folded = std.ascii.toLower(byte);
            h.update(std.mem.asBytes(&folded));
        }
        h.update(key[divider..]);
        return h.final();
    }
    pub fn eql(_: ParticipantKeyContext, a: []const u8, b: []const u8) bool {
        const left = std.mem.indexOfScalar(u8, a, 0) orelse a.len;
        const right = std.mem.indexOfScalar(u8, b, 0) orelse b.len;
        return left == right and std.ascii.eqlIgnoreCase(a[0..left], b[0..right]) and
            std.mem.eql(u8, a[left..], b[right..]);
    }
};
fn ParticipantMap(comptime T: type) type {
    return std.HashMap([]const u8, T, ParticipantKeyContext, std.hash_map.default_max_load_percentage);
}
const RoomMap = ChannelMap(*Room);
fn transportChannel(value: []const u8, out: *[128]u8) PreparedError![]const u8 {
    if (value.len == 0 or value.len > out.len) return error.InvalidRequest;
    for (value, 0..) |byte, n| {
        if (byte == 0) return error.InvalidRequest;
        out[n] = std.ascii.toLower(byte);
    }
    return out[0..value.len];
}

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

    /// Equality covers only initialized logical codec rows. Historical callers
    /// leave the unused fixed-array tail undefined; it is never authority.
    pub fn eql(self: CallProfile, other: CallProfile) bool {
        if (self.codec_count > max_profile_codecs or other.codec_count > max_profile_codecs or
            self.codec_count != other.codec_count or !std.meta.eql(self.fec, other.fec)) return false;
        for (self.slice(), other.slice()) |a, b| if (!std.meta.eql(a, b)) return false;
        return true;
    }

    /// Borrowed view of the negotiated codecs.
    pub fn slice(self: *const CallProfile) []const sdp.Codec {
        return self.codecs[0..self.codec_count];
    }
};

/// Eligibility of initialized AGREED codec families only. This projection
/// does not grant publication/JOIN authority or admit another codec tag.
pub fn agreedKindBits(profile: CallProfile) error{InvalidProfile}!u8 {
    if (profile.codec_count == 0 or profile.codec_count > max_profile_codecs) return error.InvalidProfile;
    var bits: u8 = 0;
    for (profile.slice()) |codec| bits |= switch (codec.tag) {
        .cadencevox, .opus => @as(u8, 1),
        .cadencevis, .vp8 => @as(u8, 6),
        .raw => @as(u8, 7),
    };
    return bits;
}

pub const max_snapshot_rows: usize = 4096;
pub const max_snapshot_rooms: usize = 256;
pub const SnapshotError = std.mem.Allocator.Error || error{ InvalidSnapshot, IncompleteRemap };
pub fn StringRow(comptime T: type) type {
    return struct { key: []u8, value: T };
}
pub const PhysicalProfileRow = struct { key: PhysicalProfileKey, profile: CallProfile };
pub const PhysicalMemberRow = struct { key: PhysicalMemberKey, member: PhysicalMember };
pub const RoomRow = struct { key: []u8, room: Room.Snapshot };
pub const QueueRow = struct { key: []u8, items: [][]u8 };

/// Complete owned control graph. Keys and nested queue payloads are copied;
/// unused codec and recording tails are canonicalized before they enter a DTO.
/// It carries no socket, worker, lock, or publication method.
pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    config: Config,
    transport_revision: u64,
    physical_profiles: []PhysicalProfileRow,
    physical_members: []PhysicalMemberRow,
    rooms: []RoomRow,
    breakouts: []StringRow([]u8),
    positions: []StringRow(Position),
    hands: []StringRow(void),
    profiles: []StringRow(CallProfile),
    participant_profiles: []StringRow(CallProfile),
    consents: []StringRow(void),
    recordings: []StringRow(Recording),
    qualities: []StringRow(Quality),
    queues: []QueueRow,

    pub fn deinit(self: *Snapshot) void {
        freeQueueRows(self.allocator, self.queues);
        freeStringRows(Quality, self.allocator, self.qualities);
        freeStringRows(Recording, self.allocator, self.recordings);
        freeStringRows(void, self.allocator, self.consents);
        freeStringRows(CallProfile, self.allocator, self.participant_profiles);
        freeStringRows(CallProfile, self.allocator, self.profiles);
        freeStringRows(void, self.allocator, self.hands);
        freeStringRows(Position, self.allocator, self.positions);
        freeStringRows([]u8, self.allocator, self.breakouts);
        for (self.rooms) |row| self.allocator.free(row.key);
        self.allocator.free(self.rooms);
        self.allocator.free(self.physical_members);
        self.allocator.free(self.physical_profiles);
        self.* = undefined;
    }

    pub fn validate(self: *const Snapshot) SnapshotError!void {
        if (self.config.max_participants == 0 or self.config.max_participants > max_participants or
            self.config.max_breakout_bytes > 256 or self.transport_revision == 0 or
            self.physical_profiles.len > max_snapshot_rows or self.physical_members.len > max_snapshot_rows or
            self.rooms.len > max_snapshot_rooms or self.breakouts.len > max_snapshot_rows or
            self.positions.len > max_snapshot_rows or self.hands.len > max_snapshot_rows or
            self.profiles.len > max_snapshot_rows or self.participant_profiles.len > max_snapshot_rows or
            self.consents.len > max_snapshot_rows or self.recordings.len > max_snapshot_rows or
            self.qualities.len > max_snapshot_rows or self.queues.len > max_snapshot_rows) return error.InvalidSnapshot;
        for (self.physical_profiles, 0..) |row, i| {
            if (row.key.client.isNone() or row.key.call.domain.serial == 0 or row.key.call.serial == 0 or !profileCanonical(row.profile)) return error.InvalidSnapshot;
            for (self.physical_profiles[0..i]) |prior| if (std.meta.eql(prior.key, row.key)) return error.InvalidSnapshot;
        }
        for (self.physical_members, 0..) |row, i| {
            if (row.key.client.isNone() or row.key.call.domain.serial == 0 or row.key.call.serial == 0 or
                row.member.kind_bits == 0 or row.member.kind_bits & ~@as(u8, 7) != 0) return error.InvalidSnapshot;
            media.validateParticipantId(row.member.display) catch return error.InvalidSnapshot;
            for (self.physical_members[0..i]) |prior| if (std.meta.eql(prior.key, row.key)) return error.InvalidSnapshot;
        }
        for (self.rooms, 0..) |row, i| {
            if (!validChannelKey(row.key) or row.room.len == 0 or row.room.len > self.config.max_participants) return error.InvalidSnapshot;
            row.room.validate() catch return error.InvalidSnapshot;
            for (self.rooms[0..i]) |prior| if (std.ascii.eqlIgnoreCase(prior.key, row.key)) return error.InvalidSnapshot;
        }
        try validateStringRows([]u8, self.breakouts, .composite);
        for (self.breakouts) |row| if (row.value.len > self.config.max_breakout_bytes) return error.InvalidSnapshot;
        try validateStringRows(Position, self.positions, .composite);
        try validateStringRows(void, self.hands, .composite);
        try validateStringRows(CallProfile, self.profiles, .channel);
        try validateStringRows(CallProfile, self.participant_profiles, .composite);
        try validateStringRows(void, self.consents, .composite);
        try validateStringRows(Recording, self.recordings, .channel);
        try validateStringRows(Quality, self.qualities, .composite);
        for (self.queues, 0..) |queue, i| {
            if (!validChannelKey(queue.key) or queue.items.len == 0 or queue.items.len > max_participants) return error.InvalidSnapshot;
            for (self.queues[0..i]) |prior| if (std.ascii.eqlIgnoreCase(prior.key, queue.key)) return error.InvalidSnapshot;
            var room: ?Room.Snapshot = null;
            for (self.rooms) |row| if (std.ascii.eqlIgnoreCase(row.key, queue.key)) {
                room = row.room;
                break;
            };
            const actual_room = room orelse return error.InvalidSnapshot;
            for (queue.items, 0..) |item, n| {
                _ = media.ParticipantId.init(item) catch return error.InvalidSnapshot;
                for (queue.items[0..n]) |prior| if (std.mem.eql(u8, prior, item)) return error.InvalidSnapshot;
                var joined = false;
                for (actual_room.participants[0..actual_room.len]) |participant| if (std.mem.eql(u8, participant.id.slice(), item)) {
                    joined = true;
                    break;
                };
                if (!joined) return error.InvalidSnapshot;
                var raised = false;
                for (self.hands) |hand| if (hand.key.len == queue.key.len + 1 + item.len and
                    std.ascii.eqlIgnoreCase(hand.key[0..queue.key.len], queue.key) and
                    hand.key[queue.key.len] == 0 and
                    std.mem.eql(u8, hand.key[queue.key.len + 1 ..], item))
                {
                    raised = true;
                    break;
                };
                if (!raised) return error.InvalidSnapshot;
            }
        }
    }

    /// Read-only physical join proof for a later joint Helix transaction.
    /// Every Domain endpoint has exactly one physical profile and every Domain
    /// membership has exactly one physical member with the same kind bits.
    /// The member's display must exist in the corresponding Room. Legacy
    /// nickname-only metadata remains independent and is preserved as-is.
    pub fn validateAgainstGraph(self: *const Snapshot, graph: *const routing.GraphSnapshot) SnapshotError!void {
        try self.validate();
        graph.validate() catch return error.InvalidSnapshot;
        for (self.physical_profiles) |profile| {
            var found = false;
            for (graph.endpoints) |endpoint| if (std.meta.eql(endpoint.key, profile.key)) {
                found = true;
                break;
            };
            if (!found) return error.InvalidSnapshot;
        }
        for (graph.endpoints) |endpoint| {
            var found = false;
            for (self.physical_profiles) |profile| if (std.meta.eql(profile.key, endpoint.key)) {
                found = true;
                break;
            };
            if (!found) return error.InvalidSnapshot;
        }
        for (self.physical_members) |member| {
            var found = false;
            for (graph.memberships) |row| if (std.meta.eql(row.key.call, member.key.call) and row.key.client.eql(member.key.client) and
                row.row.bits == member.member.kind_bits)
            {
                found = true;
                break;
            };
            if (!found) return error.InvalidSnapshot;
            var channel: ?[]const u8 = null;
            for (graph.calls) |call| if (std.meta.eql(call.row.id, member.key.call)) {
                channel = call.channel.bytes[0..call.channel.len];
                break;
            };
            const name = channel orelse return error.InvalidSnapshot;
            var display_found = false;
            for (self.rooms) |room| if (std.ascii.eqlIgnoreCase(room.key, name)) {
                for (room.room.participants[0..room.room.len]) |participant| if (participant.id.eql(&member.member.display) and
                    participant.joined.bits & member.member.kind_bits == member.member.kind_bits)
                {
                    display_found = true;
                    break;
                };
                break;
            };
            if (!display_found) return error.InvalidSnapshot;
        }
        for (graph.memberships) |row| {
            var found = false;
            for (self.physical_members) |member| if (std.meta.eql(member.key.call, row.key.call) and member.key.client.eql(row.key.client) and
                member.member.kind_bits == row.row.bits)
            {
                found = true;
                break;
            };
            if (!found) return error.InvalidSnapshot;
        }
    }
};

const KeyKind = enum { channel, composite };

fn validChannelKey(key: []const u8) bool {
    if (key.len == 0 or key.len > 128) return false;
    for (key) |byte| if (byte == 0) return false;
    return true;
}

fn validCompositeKey(key: []const u8) bool {
    const divider = std.mem.indexOfScalar(u8, key, 0) orelse return false;
    if (!validChannelKey(key[0..divider]) or key.len > 256) return false;
    const participant = key[divider + 1 ..];
    if (std.mem.indexOfScalar(u8, participant, 0) != null) return false;
    _ = media.ParticipantId.init(participant) catch return false;
    return true;
}

fn canonicalProfile(profile: CallProfile) SnapshotError!CallProfile {
    if (profile.codec_count > max_profile_codecs or @backingInt(profile.fec.scheme) > 2) return error.InvalidSnapshot;
    var copy = CallProfile{
        .codecs = @splat(.{ .tag = .cadencevox, .clock_rate = 0, .params = 0 }),
        .codec_count = profile.codec_count,
        .fec = profile.fec,
    };
    for (profile.codecs[0..profile.codec_count], 0..) |codec, i| {
        if (@backingInt(codec.tag) < 1 or @backingInt(codec.tag) > 3) return error.InvalidSnapshot;
        copy.codecs[i] = codec;
    }
    return copy;
}

fn profileCanonical(profile: CallProfile) bool {
    const copy = canonicalProfile(profile) catch return false;
    return std.meta.eql(copy, profile);
}

fn canonicalRecording(recording: Recording) SnapshotError!Recording {
    if (recording.by_len > recording.by_buf.len) return error.InvalidSnapshot;
    var copy = Recording{ .by_buf = @splat(0), .by_len = recording.by_len, .active = recording.active };
    @memcpy(copy.by_buf[0..recording.by_len], recording.by_buf[0..recording.by_len]);
    return copy;
}

fn validateStringRows(comptime T: type, rows: []const StringRow(T), kind: KeyKind) SnapshotError!void {
    for (rows, 0..) |row, i| {
        if (!(if (kind == .channel) validChannelKey(row.key) else validCompositeKey(row.key))) return error.InvalidSnapshot;
        for (rows[0..i]) |prior| if (if (kind == .channel)
            std.ascii.eqlIgnoreCase(prior.key, row.key)
        else
            ParticipantKeyContext.eql(.{}, prior.key, row.key)) return error.InvalidSnapshot;
        if (T == CallProfile and !profileCanonical(row.value)) return error.InvalidSnapshot;
        if (T == Recording) {
            const canonical = try canonicalRecording(row.value);
            if (!std.meta.eql(canonical, row.value)) return error.InvalidSnapshot;
        }
    }
}

fn freeStringRows(comptime T: type, allocator: std.mem.Allocator, rows: []StringRow(T)) void {
    for (rows) |row| {
        allocator.free(row.key);
        if (T == []u8) allocator.free(row.value);
    }
    allocator.free(rows);
}

fn freeQueueRows(allocator: std.mem.Allocator, rows: []QueueRow) void {
    for (rows) |row| {
        allocator.free(row.key);
        for (row.items) |item| allocator.free(item);
        allocator.free(row.items);
    }
    allocator.free(rows);
}

fn capturePhysicalProfiles(allocator: std.mem.Allocator, map: *std.AutoHashMap(PhysicalProfileKey, CallProfile)) SnapshotError![]PhysicalProfileRow {
    const rows = try allocator.alloc(PhysicalProfileRow, map.count());
    errdefer allocator.free(rows);
    var i: usize = 0;
    var it = map.iterator();
    while (it.next()) |entry| : (i += 1) rows[i] = .{ .key = entry.key_ptr.*, .profile = try canonicalProfile(entry.value_ptr.*) };
    return rows;
}

fn capturePhysicalMembers(allocator: std.mem.Allocator, map: *PhysicalMemberMap) SnapshotError![]PhysicalMemberRow {
    const rows = try allocator.alloc(PhysicalMemberRow, map.count());
    var i: usize = 0;
    var it = map.iterator();
    while (it.next()) |entry| : (i += 1) rows[i] = .{ .key = entry.key_ptr.*, .member = entry.value_ptr.* };
    return rows;
}

fn captureRooms(allocator: std.mem.Allocator, map: *RoomMap) SnapshotError![]RoomRow {
    const rows = try allocator.alloc(RoomRow, map.count());
    var i: usize = 0;
    errdefer {
        for (rows[0..i]) |row| allocator.free(row.key);
        allocator.free(rows);
    }
    var it = map.iterator();
    while (it.next()) |entry| : (i += 1) {
        const room = entry.value_ptr.*.capture() catch return error.InvalidSnapshot;
        rows[i] = .{ .key = try allocator.dupe(u8, entry.key_ptr.*), .room = room };
    }
    return rows;
}

fn captureStringRows(comptime T: type, allocator: std.mem.Allocator, map: anytype) SnapshotError![]StringRow(T) {
    const rows = try allocator.alloc(StringRow(T), map.count());
    var i: usize = 0;
    errdefer {
        for (rows[0..i]) |row| {
            allocator.free(row.key);
            if (T == []u8) allocator.free(row.value);
        }
        allocator.free(rows);
    }
    var it = map.iterator();
    while (it.next()) |entry| : (i += 1) {
        const key = try allocator.dupe(u8, entry.key_ptr.*);
        const value: T = if (T == []u8)
            allocator.dupe(u8, entry.value_ptr.*) catch |err| {
                allocator.free(key);
                return err;
            }
        else if (T == CallProfile)
            canonicalProfile(entry.value_ptr.*) catch |err| {
                allocator.free(key);
                return err;
            }
        else if (T == Recording)
            canonicalRecording(entry.value_ptr.*) catch |err| {
                allocator.free(key);
                return err;
            }
        else
            entry.value_ptr.*;
        rows[i] = .{ .key = key, .value = value };
    }
    return rows;
}

fn captureOneQueue(allocator: std.mem.Allocator, key: []const u8, items: []const []u8) SnapshotError!QueueRow {
    const owned_key = try allocator.dupe(u8, key);
    errdefer allocator.free(owned_key);
    const owned_items = try allocator.alloc([]u8, items.len);
    var i: usize = 0;
    errdefer {
        for (owned_items[0..i]) |item| allocator.free(item);
        allocator.free(owned_items);
    }
    for (items, 0..) |item, n| {
        owned_items[n] = try allocator.dupe(u8, item);
        i += 1;
    }
    return .{ .key = owned_key, .items = owned_items };
}

fn captureQueues(allocator: std.mem.Allocator, map: *ChannelMap(std.ArrayList([]u8))) SnapshotError![]QueueRow {
    const rows = try allocator.alloc(QueueRow, map.count());
    var i: usize = 0;
    errdefer {
        for (rows[0..i]) |row| {
            allocator.free(row.key);
            for (row.items) |item| allocator.free(item);
            allocator.free(row.items);
        }
        allocator.free(rows);
    }
    var it = map.iterator();
    while (it.next()) |entry| : (i += 1) rows[i] = try captureOneQueue(allocator, entry.key_ptr.*, entry.value_ptr.items);
    return rows;
}

fn remapPhysicalClient(remaps: []const routing.ClientRemap, old: routing.ClientId) SnapshotError!routing.ClientId {
    for (remaps) |entry| if (entry.source.eql(old)) return entry.target;
    return error.IncompleteRemap;
}

fn putRoomRow(result: *MediaRooms, row: RoomRow) SnapshotError!void {
    const room = try result.allocator.create(Room);
    errdefer result.allocator.destroy(room);
    room.* = Room.prepareRestore(&row.room) catch return error.InvalidSnapshot;
    const key = try result.allocator.dupe(u8, row.key);
    errdefer result.allocator.free(key);
    try result.rooms.put(key, room);
}

fn putStringRow(comptime T: type, allocator: std.mem.Allocator, map: anytype, row: StringRow(T)) SnapshotError!void {
    const key = try allocator.dupe(u8, row.key);
    errdefer allocator.free(key);
    const value: T = if (T == []u8) try allocator.dupe(u8, row.value) else row.value;
    errdefer if (T == []u8) allocator.free(value);
    try map.put(key, value);
}

fn putQueueRow(result: *MediaRooms, row: QueueRow) SnapshotError!void {
    const allocator = result.allocator;
    const key = try allocator.dupe(u8, row.key);
    errdefer allocator.free(key);
    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit(allocator);
    }
    for (row.items) |item| {
        const owned = try allocator.dupe(u8, item);
        list.append(allocator, owned) catch |err| {
            allocator.free(owned);
            return err;
        };
    }
    try result.queues.put(key, list);
}

pub const MediaRooms = struct {
    allocator: std.mem.Allocator,
    config: Config,
    /// New physical transport state is source-owned and never keyed by nickname.
    /// Ordinary display/nick methods below remain separate legacy control APIs.
    physical_profiles: std.AutoHashMap(PhysicalProfileKey, CallProfile),
    physical_members: PhysicalMemberMap,
    transport_revision: u64 = 1,
    rooms: RoomMap,
    /// Optional breakout (sub-room) label per participant, keyed by the composite
    /// "channel\x00participant". Absent = the default "main" breakout. Kept in a
    /// flat map so the substrate Session participant model stays untouched.
    breakouts: ParticipantMap([]u8),
    /// Optional spatial-audio position per participant (same composite key).
    /// Absent = origin. Value is inline (no per-entry allocation).
    positions: ParticipantMap(Position),
    /// Raised-hand set (same composite key). Presence of the key = hand raised.
    hands: ParticipantMap(void),
    /// Negotiated codec/FEC profile per channel (the call's agreed media set),
    /// keyed by an owned channel name. Established by `MEDIA OFFER`; consulted by
    /// `MEDIA ANSWER`. Cleared when the call ends.
    profiles: ChannelMap(CallProfile),
    /// Per-(channel,participant) advertised codec/FEC capability set. This is
    /// distinct from the channel profile: it records what each participant can
    /// receive so Causeway can keep the call transcode-free.
    participant_profiles: ParticipantMap(CallProfile),
    /// Visible consent bits, keyed by "channel\x00participant". Absent means
    /// the member has not consented. There is no hidden-recorder flag.
    consents: ParticipantMap(void),
    /// One oper-visible recording note per channel. The room announcement is
    /// the existence signal; this row is the stored artifact. It is not a
    /// media capture and it is cleared when the call ends.
    recordings: ChannelMap(Recording),
    /// Last congestion sample per member. Loss, RTT, chosen spatial layer,
    /// and target bitrate only — never keying material.
    qualities: ParticipantMap(Quality),
    /// Raised-hand order per channel. Index 0 is the head. The daemon lists
    /// this queue and does not refuse speech from a member who is not at the head.
    queues: ChannelMap(std.ArrayList([]u8)),

    pub fn init(allocator: std.mem.Allocator) MediaRooms {
        return initConfig(allocator, .{});
    }

    pub fn initConfig(allocator: std.mem.Allocator, config: Config) MediaRooms {
        return .{
            .allocator = allocator,
            .config = config,
            .physical_profiles = std.AutoHashMap(PhysicalProfileKey, CallProfile).init(allocator),
            .physical_members = PhysicalMemberMap.init(allocator),
            .rooms = RoomMap.init(allocator),
            .breakouts = ParticipantMap([]u8).init(allocator),
            .positions = ParticipantMap(Position).init(allocator),
            .hands = ParticipantMap(void).init(allocator),
            .profiles = ChannelMap(CallProfile).init(allocator),
            .participant_profiles = ParticipantMap(CallProfile).init(allocator),
            .consents = ParticipantMap(void).init(allocator),
            .recordings = ChannelMap(Recording).init(allocator),
            .qualities = ParticipantMap(Quality).init(allocator),
            .queues = ChannelMap(std.ArrayList([]u8)).init(allocator),
        };
    }

    pub fn deinit(self: *MediaRooms) void {
        self.physical_profiles.deinit();
        self.physical_members.deinit();
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
        var queue_it = self.queues.iterator();
        while (queue_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            for (entry.value_ptr.items) |nick| self.allocator.free(nick);
            entry.value_ptr.deinit(self.allocator);
        }
        self.queues.deinit();
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
        return self.physical_profiles.count() == 0 and self.physical_members.count() == 0 and
            self.rooms.count() == 0 and
            self.breakouts.count() == 0 and
            self.positions.count() == 0 and
            self.hands.count() == 0 and
            self.profiles.count() == 0 and
            self.participant_profiles.count() == 0 and
            self.consents.count() == 0 and
            self.recordings.count() == 0 and
            self.qualities.count() == 0 and
            self.queues.count() == 0;
    }

    /// Caller holds the World write lock across this whole copy, excluding
    /// every control-plane mutation and physical publication candidate.
    pub fn capture(self: *MediaRooms) SnapshotError!Snapshot {
        if (self.physical_profiles.count() > max_snapshot_rows or self.physical_members.count() > max_snapshot_rows or
            self.rooms.count() > max_snapshot_rooms or self.breakouts.count() > max_snapshot_rows or
            self.positions.count() > max_snapshot_rows or self.hands.count() > max_snapshot_rows or
            self.profiles.count() > max_snapshot_rows or self.participant_profiles.count() > max_snapshot_rows or
            self.consents.count() > max_snapshot_rows or self.recordings.count() > max_snapshot_rows or
            self.qualities.count() > max_snapshot_rows or self.queues.count() > max_snapshot_rows) return error.InvalidSnapshot;
        const a = self.allocator;
        const physical_profiles = try capturePhysicalProfiles(a, &self.physical_profiles);
        errdefer a.free(physical_profiles);
        const physical_members = try capturePhysicalMembers(a, &self.physical_members);
        errdefer a.free(physical_members);
        const rooms = try captureRooms(a, &self.rooms);
        errdefer {
            for (rooms) |row| a.free(row.key);
            a.free(rooms);
        }
        const breakouts = try captureStringRows([]u8, a, &self.breakouts);
        errdefer freeStringRows([]u8, a, breakouts);
        const positions = try captureStringRows(Position, a, &self.positions);
        errdefer freeStringRows(Position, a, positions);
        const hands = try captureStringRows(void, a, &self.hands);
        errdefer freeStringRows(void, a, hands);
        const profiles = try captureStringRows(CallProfile, a, &self.profiles);
        errdefer freeStringRows(CallProfile, a, profiles);
        const participant_profiles = try captureStringRows(CallProfile, a, &self.participant_profiles);
        errdefer freeStringRows(CallProfile, a, participant_profiles);
        const consents = try captureStringRows(void, a, &self.consents);
        errdefer freeStringRows(void, a, consents);
        const recordings = try captureStringRows(Recording, a, &self.recordings);
        errdefer freeStringRows(Recording, a, recordings);
        const qualities = try captureStringRows(Quality, a, &self.qualities);
        errdefer freeStringRows(Quality, a, qualities);
        const queues = try captureQueues(a, &self.queues);
        errdefer freeQueueRows(a, queues);
        const snapshot = Snapshot{
            .allocator = a,
            .config = self.config,
            .transport_revision = self.transport_revision,
            .physical_profiles = physical_profiles,
            .physical_members = physical_members,
            .rooms = rooms,
            .breakouts = breakouts,
            .positions = positions,
            .hands = hands,
            .profiles = profiles,
            .participant_profiles = participant_profiles,
            .consents = consents,
            .recordings = recordings,
            .qualities = qualities,
            .queues = queues,
        };
        try snapshot.validate();
        return snapshot;
    }

    /// Build an independent control graph. The caller supplies the same full
    /// physical remap used by Domain; this leaf checks every ClientId it owns
    /// and refuses duplicate source or target identities before allocating.
    /// Returning this value does not install it into the daemon.
    pub fn prepareRestore(allocator: std.mem.Allocator, snapshot: *const Snapshot, remaps: []const routing.ClientRemap) SnapshotError!MediaRooms {
        try snapshot.validate();
        if (remaps.len > routing.max_graph_rows * 2) return error.InvalidSnapshot;
        for (remaps, 0..) |entry, i| {
            if (entry.source.isNone() or entry.target.isNone()) return error.InvalidSnapshot;
            for (remaps[0..i]) |prior| if (prior.source.eql(entry.source) or prior.target.eql(entry.target)) return error.InvalidSnapshot;
        }
        for (snapshot.physical_profiles) |row| _ = try remapPhysicalClient(remaps, row.key.client);
        for (snapshot.physical_members) |row| _ = try remapPhysicalClient(remaps, row.key.client);
        var result = MediaRooms.initConfig(allocator, snapshot.config);
        errdefer result.deinit();
        result.transport_revision = snapshot.transport_revision;
        for (snapshot.physical_profiles) |row| {
            var key = row.key;
            key.client = try remapPhysicalClient(remaps, key.client);
            try result.physical_profiles.put(key, row.profile);
        }
        for (snapshot.physical_members) |row| {
            var key = row.key;
            key.client = try remapPhysicalClient(remaps, key.client);
            try result.physical_members.put(key, row.member);
        }
        for (snapshot.rooms) |row| try putRoomRow(&result, row);
        for (snapshot.breakouts) |row| try putStringRow([]u8, allocator, &result.breakouts, row);
        for (snapshot.positions) |row| try putStringRow(Position, allocator, &result.positions, row);
        for (snapshot.hands) |row| try putStringRow(void, allocator, &result.hands, row);
        for (snapshot.profiles) |row| try putStringRow(CallProfile, allocator, &result.profiles, row);
        for (snapshot.participant_profiles) |row| try putStringRow(CallProfile, allocator, &result.participant_profiles, row);
        for (snapshot.consents) |row| try putStringRow(void, allocator, &result.consents, row);
        for (snapshot.recordings) |row| try putStringRow(Recording, allocator, &result.recordings, row);
        for (snapshot.qualities) |row| try putStringRow(Quality, allocator, &result.qualities, row);
        for (snapshot.queues) |row| try putQueueRow(&result, row);
        return result;
    }

    /// Build the "channel\x00participant" composite key into `buf`.
    fn breakoutKey(buf: []u8, channel: []const u8, pid: []const u8) ?[]const u8 {
        if (!validChannelKey(channel) or std.mem.indexOfScalar(u8, pid, 0) != null) return null;
        _ = media.ParticipantId.init(pid) catch return null;
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
        if (raised) self.enqueueSpeaker(channel, pid) catch |e| {
            self.clearHand(channel, pid);
            return e;
        };
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
        self.dequeueSpeaker(channel, pid);
    }

    /// Append `pid` to the channel queue unless they are already in it.
    /// A non-participant is not queued. The head stays whoever raised first.
    fn enqueueSpeaker(self: *MediaRooms, channel: []const u8, pid: []const u8) Error!void {
        if (!self.isParticipant(channel, pid)) return;
        const gop = try self.queues.getOrPut(channel);
        if (!gop.found_existing) {
            gop.value_ptr.* = .empty;
            gop.key_ptr.* = self.allocator.dupe(u8, channel) catch |e| {
                _ = self.queues.remove(channel);
                return e;
            };
        }
        for (gop.value_ptr.items) |existing| {
            if (std.mem.eql(u8, existing, pid)) return;
        }
        if (gop.value_ptr.items.len >= max_participants) return error.ParticipantCapacityExceeded;
        const owned = self.allocator.dupe(u8, pid) catch |e| return e;
        gop.value_ptr.append(self.allocator, owned) catch |e| {
            self.allocator.free(owned);
            return e;
        };
    }

    fn dequeueSpeaker(self: *MediaRooms, channel: []const u8, pid: []const u8) void {
        const q = self.queues.getPtr(channel) orelse return;
        var i: usize = 0;
        while (i < q.items.len) {
            if (std.mem.eql(u8, q.items[i], pid)) {
                const owned = q.orderedRemove(i);
                self.allocator.free(owned);
                break;
            }
            i += 1;
        }
        if (q.items.len == 0) self.clearQueue(channel);
    }

    fn clearQueue(self: *MediaRooms, channel: []const u8) void {
        if (self.queues.fetchRemove(channel)) |kv| {
            for (kv.value.items) |nick| self.allocator.free(nick);
            var list = kv.value;
            list.deinit(self.allocator);
            self.allocator.free(kv.key);
        }
    }

    /// Copy the speaking queue, head first, into `out`. Returns how many names fit.
    pub fn copySpeakQueue(self: *const MediaRooms, channel: []const u8, out: [][]const u8) usize {
        const q = self.queues.get(channel) orelse return 0;
        const n = @min(out.len, q.items.len);
        for (q.items[0..n], 0..) |nick, i| out[i] = nick;
        return n;
    }

    /// The room for `channel`, or null when no call is active there.
    pub fn room(self: *MediaRooms, channel: []const u8) ?*Room {
        return self.rooms.get(channel);
    }

    /// Prepare all actually offered physical legs in ONE OLD/FINAL map plan.
    /// Caller owns World/control serialization across capture/preparation; final
    /// validate/commit uses the shared routing cut. No live capacity grows here.
    pub fn prepareTransportProfiles(
        self: *MediaRooms,
        keys: []const PhysicalProfileKey,
        channel_input: []const u8,
        display_nick: []const u8,
        shared: ?CallProfile,
        advertised: CallProfile,
    ) PreparedError!*PreparedProfiles {
        var channel_buf: [128]u8 = undefined;
        const channel = try transportChannel(channel_input, &channel_buf);
        if (keys.len == 0 or keys.len > 2 or channel.len == 0 or channel.len > 128 or display_nick.len == 0 or display_nick.len > 64) return error.InvalidRequest;
        try validateProfile(advertised);
        if (shared) |profile| try validateProfile(profile);
        for (keys, 0..) |key, n| {
            if (key.client.isNone() or key.call.domain.serial == 0 or key.call.serial == 0) return error.InvalidIdentity;
            if (!std.meta.eql(keys[0].call, key.call) or !keys[0].client.eql(key.client)) return error.InvalidIdentity;
            for (keys[0..n]) |prior| if (prior.leg == key.leg) return error.InvalidRequest;
        }
        if (self.transport_revision == std.math.maxInt(u64)) return error.SequenceExhausted;
        const plan = try self.allocator.create(ProfilePlan);
        plan.* = .{ .owner = self, .revision = self.transport_revision, .keys = @splat(std.mem.zeroes(PhysicalProfileKey)), .count = @intCast(keys.len), .old_call = self.profiles.get(channel), .old_call_key = if (self.profiles.getEntry(channel)) |entry| @intFromPtr(entry.key_ptr.*.ptr) else 0, .shared = shared, .advertised = advertised, .calls_state = mapState(self.profiles), .physical_state = mapState(self.physical_profiles) };
        errdefer self.allocator.destroy(plan);
        errdefer {
            if (plan.physical_growth) |*map| map.deinit();
            if (plan.call_growth) |*map| map.deinit();
            if (plan.new_call_key) |owned| self.allocator.free(owned);
        }
        plan.channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(plan.channel);
        const nick_len = @min(display_nick.len, plan.display_nick.len);
        @memcpy(plan.display_nick[0..nick_len], display_nick[0..nick_len]);
        plan.display_len = @intCast(nick_len);
        var extra: u32 = 0;
        for (keys, 0..) |key, n| {
            plan.keys[n] = key;
            plan.old[n] = self.physical_profiles.get(key);
            if (plan.old[n] == null) extra += 1;
        }
        const required = std.math.add(u32, self.physical_profiles.count(), extra) catch return error.SequenceExhausted;
        if (extra > self.physical_profiles.unmanaged.available) {
            plan.physical_growth = std.AutoHashMap(PhysicalProfileKey, CallProfile).init(self.allocator);
            try plan.physical_growth.?.ensureTotalCapacity(required);
        }
        if (shared != null and plan.old_call == null) {
            plan.new_call_key = try self.allocator.dupe(u8, channel);
            if (self.profiles.unmanaged.available == 0) {
                const count = std.math.add(u32, self.profiles.count(), 1) catch return error.SequenceExhausted;
                plan.call_growth = ChannelMap(CallProfile).init(self.allocator);
                try plan.call_growth.?.ensureTotalCapacity(count);
            }
        }
        return @ptrCast(plan);
    }

    /// Public codec negotiation without any issued endpoint or secret. The
    /// final caller independently validates its current source negotiation;
    /// this candidate validates only this actual Room's captured OLD profile.
    pub fn prepareSharedProfile(self: *MediaRooms, channel_input: []const u8, agreed: CallProfile) PreparedError!*PreparedSharedProfile {
        _ = try agreedKindBits(agreed);
        var channel_buf: [128]u8 = undefined;
        const channel = try transportChannel(channel_input, &channel_buf);
        if (self.transport_revision == std.math.maxInt(u64)) return error.SequenceExhausted;
        const plan = try self.allocator.create(SharedProfilePlan);
        plan.* = .{ .owner = self, .revision = self.transport_revision, .old = self.profiles.get(channel), .old_key = if (self.profiles.getEntry(channel)) |entry| @intFromPtr(entry.key_ptr.*.ptr) else 0, .state = mapState(self.profiles), .agreed = agreed };
        errdefer self.allocator.destroy(plan);
        errdefer {
            if (plan.growth) |*map| map.deinit();
            if (plan.new_key) |key| self.allocator.free(key);
            self.allocator.free(plan.channel);
        }
        plan.channel = try self.allocator.dupe(u8, channel);
        if (plan.old == null) {
            plan.new_key = try self.allocator.dupe(u8, channel);
            if (self.profiles.unmanaged.available == 0) {
                const required = std.math.add(u32, self.profiles.count(), 1) catch return error.SequenceExhausted;
                plan.growth = ChannelMap(CallProfile).init(self.allocator);
                try plan.growth.?.ensureTotalCapacity(required);
            }
        }
        return @ptrCast(plan);
    }

    pub fn transportProfileOf(self: *const MediaRooms, channel: []const u8) ?CallProfile {
        var buf: [128]u8 = undefined;
        const key = transportChannel(channel, &buf) catch return null;
        return self.profiles.get(key);
    }
    pub fn physicalProfileOf(self: *const MediaRooms, key: PhysicalProfileKey) ?CallProfile {
        return self.physical_profiles.get(key);
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
        // Capability rows can exist before JOIN. Drain every matching row in
        // bounded batches instead of silently retaining rows beyond room cap.
        while (true) {
            var victims: [max_participants][]const u8 = undefined;
            var n: usize = 0;
            var it = self.participant_profiles.keyIterator();
            while (it.next()) |key| {
                const k = key.*;
                if (k.len <= channel.len or k[channel.len] != 0) continue;
                if (!std.ascii.eqlIgnoreCase(k[0..channel.len], channel)) continue;
                victims[n] = k;
                n += 1;
                if (n == victims.len) break;
            }
            if (n == 0) return;
            for (victims[0..n]) |key| {
                _ = self.participant_profiles.remove(key);
                self.allocator.free(key);
            }
        }
    }

    /// Prepare the exact logical room change belonging to an actual physical
    /// Domain JOIN candidate. The graph owner also stages its own attachment,
    /// E2EE and protected reply custody before any joined publication.
    pub fn prepareJoin(self: *MediaRooms, membership: routing.MembershipPreview, channel_input: []const u8, display_nick: []const u8, kind: MediaKind) PreparedError!*PreparedJoin {
        var channel_buf: [128]u8 = undefined;
        const channel = try transportChannel(channel_input, &channel_buf);
        if (membership.client.isNone() or membership.call.domain.serial == 0 or membership.call.serial == 0 or
            membership.kind_bits & (@as(u8, 1) << @backingInt(kind)) == 0) return error.InvalidIdentity;
        if (channel.len == 0 or channel.len > 128) return error.InvalidRequest;
        const id = try media.ParticipantId.init(display_nick);
        const member_key = PhysicalMemberKey{ .call = membership.call, .client = membership.client };
        const old_member = self.physical_members.get(member_key);
        // NICK changes require the real departure/re-registration transaction;
        // overwriting display here would leave an unrelated logical member.
        if (old_member) |prior| if (!prior.display.eql(&id)) return error.StaleCandidate;
        if (self.transport_revision == std.math.maxInt(u64)) return error.SequenceExhausted;
        const old_room = self.rooms.get(channel);
        if (old_member != null and old_room == null) return error.InvalidSnapshot;
        const old_snapshot = if (old_room) |room_ptr| try room_ptr.capture() else Room.Snapshot{};
        var final_room = try Room.prepareRestore(&old_snapshot);
        if (final_room.participant(id) == null and final_room.count() >= @min(self.config.max_participants, max_participants)) return error.ParticipantCapacityExceeded;
        try final_room.join(id, kind);
        const plan = try self.allocator.create(JoinPlan);
        plan.* = .{ .owner = self, .membership = membership, .member_key = member_key, .old_member = old_member, .next_member = .{ .display = id, .kind_bits = membership.kind_bits }, .members_state = mapState(self.physical_members), .revision = self.transport_revision, .rooms_state = mapState(self.rooms), .old_room = old_room, .old_key = if (self.rooms.getEntry(channel)) |entry| @intFromPtr(entry.key_ptr.*.ptr) else 0, .old_snapshot = old_snapshot };
        errdefer self.allocator.destroy(plan);
        errdefer {
            if (plan.member_growth) |*map| map.deinit();
            if (plan.growth) |*map| map.deinit();
            if (plan.new_key) |owned| self.allocator.free(owned);
        }
        if (old_member == null and self.physical_members.unmanaged.available == 0) {
            plan.member_growth = PhysicalMemberMap.init(self.allocator);
            const required = std.math.add(u32, self.physical_members.count(), 1) catch return error.SequenceExhausted;
            try plan.member_growth.?.ensureTotalCapacity(required);
        }
        plan.channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(plan.channel);
        plan.replacement = try self.allocator.create(Room);
        errdefer self.allocator.destroy(plan.replacement.?);
        plan.replacement.?.* = final_room;
        if (old_room == null) {
            plan.new_key = try self.allocator.dupe(u8, channel);
            if (self.rooms.unmanaged.available == 0) {
                plan.growth = RoomMap.init(self.allocator);
                const required = std.math.add(u32, self.rooms.count(), 1) catch return error.SequenceExhausted;
                try plan.growth.?.ensureTotalCapacity(required);
            }
        }
        return @ptrCast(plan);
    }

    /// Exact source-owned logical/profile retirement joined to the Domain
    /// departure. All affected payloads remain owned here until after the cut.
    pub fn prepareDeparture(self: *MediaRooms, departure: *routing.PreparedDeparture, channel_input: []const u8) PreparedError!*PreparedRoomDeparture {
        return self.prepareDepartureWithExternalOwners(departure, channel_input, EmptyExternalOwners{});
    }

    /// A descriptor borrowed from the server's original physical registry under
    /// its uninterrupted World cut. It preserves legacy room display only and
    /// grants no Domain membership, transport endpoint, or packet authority.
    pub const ExternalDepartureOwner = struct {
        channel: []const u8,
        participant: media.ParticipantId,
        client: routing.ClientId,
        kind_bits: u8,
    };
    const EmptyExternalOwners = struct {
        fn next(_: *@This()) PreparedError!?ExternalDepartureOwner {
            return null;
        }
    };

    /// Enumerate the current external-owner census BEFORE the prepared cut.
    /// Nothing borrowed from the iterator survives this preparation. The server
    /// retains World through all joined validations/commits, while this plan
    /// independently validates physical-map and room revisions/snapshots.
    pub fn prepareDepartureWithExternalOwners(self: *MediaRooms, departure: *routing.PreparedDeparture, channel_input: []const u8, external_owners: anytype) PreparedError!*PreparedRoomDeparture {
        var channel_buf: [128]u8 = undefined;
        const channel = try transportChannel(channel_input, &channel_buf);
        if (channel.len == 0 or channel.len > 128) return error.InvalidRequest;
        const key = departure.ownerKey(.native);
        const member_key = PhysicalMemberKey{ .call = key.call, .client = key.client };
        const old_member = self.physical_members.get(member_key);
        const old_room = self.rooms.get(channel);
        if (old_member != null and old_room == null) return error.InvalidSnapshot;
        const old_snapshot = if (old_room) |room_ptr| try room_ptr.capture() else Room.Snapshot{};
        var final_room = try Room.prepareRestore(&old_snapshot);
        var external_before: u8 = 0;
        var external_remaining: u8 = 0;
        var external_display: ?media.ParticipantId = null;
        var external_owned = false;
        var owners = external_owners;
        while (try owners.next()) |external| {
            media.validateParticipantId(external.participant) catch return error.InvalidRequest;
            if (external.client.isNone() or external.kind_bits == 0 or external.kind_bits & ~@as(u8, 7) != 0 or !std.ascii.eqlIgnoreCase(external.channel, channel)) return error.InvalidRequest;
            if (old_member) |row| if (!row.display.eql(&external.participant)) return error.InvalidRequest;
            if (external_display) |display| if (!display.eql(&external.participant)) return error.InvalidRequest;
            external_display = external.participant;
            // A protected physical member already contributes its exact bits
            // to the graph census below. Never count it again as legacy.
            if (self.physical_members.get(.{ .call = key.call, .client = external.client })) |protected| {
                if (!protected.display.eql(&external.participant)) return error.InvalidSnapshot;
                continue;
            }
            external_before |= external.kind_bits;
            if (!external.client.eql(key.client)) external_remaining |= external.kind_bits else external_owned = true;
        }
        const affected_display: ?media.ParticipantId = if (old_member) |row| row.display else external_display;
        const room_update = old_member != null or external_owned;
        var clear_display = false;
        if (affected_display) |display| {
            var all_bits: u8 = external_before;
            var remaining: u8 = external_remaining;
            var it = self.physical_members.iterator();
            while (it.next()) |entry| if (std.meta.eql(entry.key_ptr.call, key.call) and entry.value_ptr.display.eql(&display)) {
                all_bits |= entry.value_ptr.kind_bits;
                if (!entry.key_ptr.client.eql(key.client)) remaining |= entry.value_ptr.kind_bits;
            };
            const actual = final_room.participant(display) orelse return error.InvalidSnapshot;
            if (actual.joined.bits != all_bits) return error.InvalidSnapshot;
            if (room_update) {
                for ([_]MediaKind{ .voice, .video, .screen }) |kind| {
                    const bit = @as(u8, 1) << @backingInt(kind);
                    if (all_bits & bit != 0 and remaining & bit == 0) try final_room.leave(display, kind);
                }
                clear_display = remaining == 0;
            }
        }
        const terminal = departure.isTerminal();
        if (!terminal and self.transport_revision == std.math.maxInt(u64)) return error.SequenceExhausted;
        const plan = try self.allocator.create(RoomDeparturePlan);
        plan.* = .{ .owner = self, .key = member_key, .revision = self.transport_revision, .terminal = terminal, .batch_part = departure.isBatchPart(), .old_member = old_member, .members_state = mapState(self.physical_members), .physical_state = mapState(self.physical_profiles), .old_room = old_room, .old_room_key = if (self.rooms.getEntry(channel)) |entry| entry.key_ptr.* else null, .old_snapshot = old_snapshot, .affected_display = affected_display, .room_update = room_update, .drop_room = room_update and final_room.count() == 0, .clear_display = clear_display, .clear_shared = departure.removesCall() and final_room.count() == 0, .final_room_empty = final_room.count() == 0 };
        errdefer self.allocator.destroy(plan);
        errdefer {
            if (plan.replacement) |owned| self.allocator.destroy(owned);
            self.allocator.free(plan.member_lookup);
        }
        plan.channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(plan.channel);
        for ([_]routing.Leg{ .native, .webrtc }, 0..) |leg, n| plan.old_profiles[n] = self.physical_profiles.get(departure.ownerKey(leg));
        if (room_update and !plan.drop_room) {
            plan.replacement = try self.allocator.create(Room);
            plan.replacement.?.* = final_room;
        }
        if (clear_display) {
            var buf: [256]u8 = undefined;
            const lookup = breakoutKey(&buf, channel, affected_display.?.slice()) orelse return error.InvalidRequest;
            plan.member_lookup = try self.allocator.dupe(u8, lookup);
            plan.breakout = captureStored([]u8, self.breakouts, lookup);
            plan.position = captureStored(Position, self.positions, lookup);
            plan.hand = captureStored(void, self.hands, lookup);
            plan.participant_profile = captureStored(CallProfile, self.participant_profiles, lookup);
            plan.consent = captureStored(void, self.consents, lookup);
            plan.quality = captureStored(Quality, self.qualities, lookup);
        }
        plan.queue = captureStored(std.ArrayList([]u8), self.queues, channel);
        if (plan.drop_room) plan.recording = captureStored(Recording, self.recordings, channel);
        if (plan.clear_shared) plan.shared = captureStored(CallProfile, self.profiles, channel);
        return @ptrCast(plan);
    }

    /// Prepare all calls owned by one actual physical client against the same
    /// source revision. Complete leaf/source validation precedes every removal.
    pub fn prepareClientDeparture(self: *MediaRooms, departure: *routing.PreparedClientDeparture) PreparedError!*PreparedRoomClientDeparture {
        const plan = try self.allocator.create(RoomClientDeparturePlan);
        errdefer self.allocator.destroy(plan);
        const parts = try self.allocator.alloc(*PreparedRoomDeparture, departure.count());
        errdefer self.allocator.free(parts);
        var initialized: usize = 0;
        errdefer for (parts[0..initialized]) |part| part.deinit();
        const revision = self.transport_revision;
        for (parts, 0..) |*part, n| {
            const source = departure.part(n);
            part.* = try self.prepareDeparture(source, source.channel());
            initialized += 1;
        }
        plan.* = .{ .owner = self, .departure = departure, .parts = parts, .revision = revision };
        return @ptrCast(plan);
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

    fn dropRoom(self: *MediaRooms, entry: RoomMap.Entry) void {
        const key = entry.key_ptr.*;
        const r = entry.value_ptr.*;
        self.clearProfile(key);
        self.clearRecording(key);
        self.clearQueue(key);
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

fn graphObservationForRoomsTest(call: routing.CallId, owner: routing.ClientId, leg: routing.Leg, serial: u64, stream: u32) routing.EndpointObservation {
    const endpoint = routing.EndpointId{ .call = call, .serial = serial, .leg = leg };
    return .{
        .reference = .{ .endpoint = endpoint, .offering_client = owner, .bridge_policy_revision = 1 },
        .stamp = .{ .endpoint = endpoint, .binding_revision = 1, .security_revision = 1, .offering_client = owner },
        .stream_id = stream,
        .mode = if (leg == .webrtc) .dtls_required else .legacy_group,
    };
}

test "media rooms owned graph snapshot roundtrip preserves all control maps and physical remap" {
    var rooms = MediaRooms.initConfig(testing.allocator, .{ .max_participants = 8, .max_breakout_bytes = 16 });
    defer rooms.deinit();
    const call = routing.CallId{ .domain = .{ .serial = 9 }, .serial = 4 };
    const old_a = routing.ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    const old_b = routing.ClientId{ .shard = 0, .slot = 2, .gen = 1 };
    const new_a = routing.ClientId{ .shard = 2, .slot = 11, .gen = 3 };
    const new_b = routing.ClientId{ .shard = 2, .slot = 12, .gen = 3 };
    const codec = sdp.Codec{ .tag = .cadencevox, .clock_rate = 48000, .params = 0 };
    const profile = CallProfile{ .codecs = .{ codec, undefined, undefined, undefined }, .codec_count = 1 };
    try rooms.physical_profiles.put(.{ .call = call, .client = old_a, .leg = .native }, profile);
    try rooms.physical_profiles.put(.{ .call = call, .client = old_b, .leg = .webrtc }, profile);
    try rooms.physical_members.put(.{ .call = call, .client = old_a }, .{ .display = try media.ParticipantId.init("alice"), .kind_bits = 1 });
    try rooms.physical_members.put(.{ .call = call, .client = old_b }, .{ .display = try media.ParticipantId.init("bob"), .kind_bits = 2 });
    rooms.transport_revision = 17;
    try rooms.join("#media", "alice", .voice);
    try rooms.join("#media", "bob", .video);
    try rooms.setBreakout("#media", "alice", "stage");
    try rooms.setPosition("#media", "alice", .{ .x = 7, .y = -4 });
    try rooms.setHand("#media", "alice", true);
    try rooms.setProfile("#media", &.{codec}, .{ .scheme = .none, .redundancy = 0 });
    try rooms.setParticipantProfile("#media", "alice", &.{codec}, .{ .scheme = .none, .redundancy = 0 });
    try testing.expect(try rooms.setConsent("#media", "alice", true));
    try testing.expect(try rooms.setConsent("#media", "bob", true));
    try testing.expect(try rooms.startRecording("#media", "alice"));
    try testing.expect(try rooms.setQuality("#media", "alice", .{ .loss_pct = 3, .rtt_ms = 41, .bitrate_kbps = 256 }));
    var snapshot = try rooms.capture();
    defer snapshot.deinit();
    try snapshot.validate();
    const graph_calls = try testing.allocator.dupe(routing.GraphCall, &.{.{ .channel = try routing.ChannelKey.init("#media"), .row = .{ .id = call, .offers = 2, .memberships = 2 } }});
    defer testing.allocator.free(graph_calls);
    const graph_endpoints = try testing.allocator.dupe(routing.GraphEndpoint, &.{
        .{ .key = .{ .call = call, .client = old_a, .leg = .native }, .row = .{ .observation = graphObservationForRoomsTest(call, old_a, .native, 5, 5) } },
        .{ .key = .{ .call = call, .client = old_b, .leg = .webrtc }, .row = .{ .observation = graphObservationForRoomsTest(call, old_b, .webrtc, 6, 6) } },
    });
    defer testing.allocator.free(graph_endpoints);
    const graph_memberships = try testing.allocator.dupe(routing.GraphMembership, &.{
        .{ .key = .{ .call = call, .client = old_a }, .row = .{ .bits = 1 } },
        .{ .key = .{ .call = call, .client = old_b }, .row = .{ .bits = 2 } },
    });
    defer testing.allocator.free(graph_memberships);
    const graph_profile = CallProfile{
        .codecs = .{ codec, .{ .tag = .cadencevox, .clock_rate = 0, .params = 0 }, .{ .tag = .cadencevox, .clock_rate = 0, .params = 0 }, .{ .tag = .cadencevox, .clock_rate = 0, .params = 0 } },
        .codec_count = 1,
    };
    const graph_policies = try testing.allocator.dupe(routing.GraphBridgePolicy, &.{.{
        .key = .{ .call = call, .client = old_a, .leg = .native },
        .row = .{ .reference = graphObservationForRoomsTest(call, old_a, .native, 5, 5).reference, .profile = graph_profile, .kind_bits = 1 },
    }});
    defer testing.allocator.free(graph_policies);
    const graph = routing.GraphSnapshot{
        .allocator = testing.allocator,
        .id = .{ .serial = 9 },
        .revision = 17,
        .next_call = 5,
        .next_endpoint = 7,
        .next_stream = 7,
        .next_scope = 1,
        .next_binding = 3,
        .native_binding_serial = 1,
        .webrtc_binding_serial = 2,
        .calls = graph_calls,
        .endpoints = graph_endpoints,
        .memberships = graph_memberships,
        .bridge_policy = graph_policies,
    };
    try snapshot.validateAgainstGraph(&graph);
    snapshot.rooms[0].key[1] = 'M';
    try snapshot.validateAgainstGraph(&graph);
    snapshot.rooms[0].key[1] = 'm';
    graph_policies[0].row.kind_bits = 2;
    try testing.expectError(error.InvalidSnapshot, graph.validate());
    graph_policies[0].row.kind_bits = 1;
    const original_profile_client = snapshot.physical_profiles[0].key.client;
    snapshot.physical_profiles[0].key.client = new_a;
    try testing.expectError(error.InvalidSnapshot, snapshot.validateAgainstGraph(&graph));
    snapshot.physical_profiles[0].key.client = original_profile_client;
    const original_display = snapshot.physical_members[0].member.display;
    snapshot.physical_members[0].member.display = try media.ParticipantId.init("stranger");
    try testing.expectError(error.InvalidSnapshot, snapshot.validateAgainstGraph(&graph));
    snapshot.physical_members[0].member.display = original_display;
    snapshot.queues[0].items[0][0] = 'x';
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.queues[0].items[0][0] = 'a';
    try testing.expectEqual(@as(usize, 2), snapshot.physical_profiles.len);
    try testing.expectEqual(@as(usize, 2), snapshot.physical_members.len);
    try testing.expectEqual(@as(usize, 1), snapshot.rooms.len);
    try testing.expectEqual(@as(usize, 1), snapshot.queues.len);
    try testing.expectEqual(@as(usize, 1), snapshot.recordings.len);
    var restored = try MediaRooms.prepareRestore(testing.allocator, &snapshot, &.{ .{ .source = old_a, .target = new_a }, .{ .source = old_b, .target = new_b } });
    defer restored.deinit();
    try testing.expectEqual(@as(u64, 17), restored.transport_revision);
    try testing.expect(restored.physical_profiles.contains(.{ .call = call, .client = new_a, .leg = .native }));
    try testing.expect(restored.physical_profiles.contains(.{ .call = call, .client = new_b, .leg = .webrtc }));
    try testing.expect(!restored.physical_members.contains(.{ .call = call, .client = old_a }));
    try testing.expectEqual(@as(usize, 2), restored.roster("#media").len);
    try testing.expect(std.mem.eql(u8, "stage", restored.breakoutOf("#media", "alice")));
    try testing.expectEqual(Position{ .x = 7, .y = -4 }, restored.positionOf("#media", "alice"));
    try testing.expect(restored.handRaised("#media", "alice"));
    try testing.expect(restored.hasConsent("#media", "bob"));
    try testing.expect(restored.recordingOf("#media").?.active);
    try testing.expectEqual(@as(u8, 3), restored.qualityOf("#media", "alice").?.loss_pct);
    var queue: [2][]const u8 = undefined;
    try testing.expectEqual(@as(usize, 1), restored.copySpeakQueue("#media", &queue));
    try testing.expect(std.mem.eql(u8, "alice", queue[0]));
    var recaptured = try restored.capture();
    defer recaptured.deinit();
    try recaptured.validate();
    var remapped_graph = try routing.prepareRemappedGraph(testing.allocator, &graph, &.{ .{ .source = old_a, .target = new_a }, .{ .source = old_b, .target = new_b } });
    defer remapped_graph.deinit();
    try recaptured.validateAgainstGraph(&remapped_graph);
    try testing.expectError(error.IncompleteRemap, MediaRooms.prepareRestore(testing.allocator, &snapshot, &.{.{ .source = old_a, .target = new_a }}));
    try testing.expectError(error.InvalidSnapshot, MediaRooms.prepareRestore(testing.allocator, &snapshot, &.{ .{ .source = old_a, .target = new_a }, .{ .source = old_b, .target = new_a } }));
    const saved = snapshot.rooms[0].room.participants[0].id.len;
    snapshot.rooms[0].room.participants[0].id.len = 0;
    try testing.expectError(error.InvalidSnapshot, MediaRooms.prepareRestore(testing.allocator, &snapshot, &.{ .{ .source = old_a, .target = new_a }, .{ .source = old_b, .target = new_b } }));
    snapshot.rooms[0].room.participants[0].id.len = saved;
}

test "room names use ASCII case without merging snapshot aliases or Unicode" {
    var rooms = MediaRooms.init(testing.allocator);
    defer rooms.deinit();
    try rooms.join("#ALPHA", "alice", .voice);
    try rooms.join("#alpha", "bob", .video);
    try testing.expectEqual(@as(u32, 1), rooms.rooms.count());
    try testing.expect(rooms.isParticipant("#AlPhA", "alice"));
    try testing.expect(rooms.isParticipant("#alpha", "bob"));
    try testing.expect(!rooms.isParticipant("#alpha", "other"));
    const oversized: [129]u8 = @splat('A');
    try testing.expect(!rooms.isParticipant(&oversized, "alice"));
    var snapshot = try rooms.capture();
    defer snapshot.deinit();
    try testing.expectEqualStrings("#ALPHA", snapshot.rooms[0].key);
    var restored = try MediaRooms.prepareRestore(testing.allocator, &snapshot, &.{});
    defer restored.deinit();
    const entry = restored.rooms.getEntry("#alpha").?;
    try testing.expectEqualStrings("#ALPHA", entry.key_ptr.*);
    try testing.expect(restored.isParticipant("#aLpHa", "alice"));

    try rooms.join("#é", "utf", .voice);
    try testing.expect(!rooms.isParticipant("#É", "utf"));
    try rooms.join("#É", "other", .voice);
    try testing.expectEqual(@as(u32, 3), rooms.rooms.count());

    var aliases = try rooms.capture();
    defer aliases.deinit();
    // Give two individually valid rows ASCII-equivalent keys without changing
    // the live map. Validation must refuse them before restoration allocates.
    const lower_alias = try testing.allocator.dupe(u8, "#alpha");
    testing.allocator.free(aliases.rooms[1].key);
    aliases.rooms[1].key = lower_alias;
    // The map iteration order is unspecified: make the other key explicit.
    const upper_alias = try testing.allocator.dupe(u8, "#ALPHA");
    testing.allocator.free(aliases.rooms[0].key);
    aliases.rooms[0].key = upper_alias;
    try testing.expectError(error.InvalidSnapshot, aliases.validate());
    try testing.expectError(error.InvalidSnapshot, MediaRooms.prepareRestore(testing.allocator, &aliases, &.{}));
}

test "media rooms prepared graph every allocation failure leaves source and permits retry" {
    var rooms = MediaRooms.init(testing.allocator);
    defer rooms.deinit();
    try rooms.join("#OOM", "alice", .voice);
    try rooms.setHand("#oom", "alice", true);
    try rooms.setBreakout("#oom", "alice", "stage");
    var snapshot = try rooms.capture();
    defer snapshot.deinit();
    var fail = testing.FailingAllocator.init(testing.allocator, .{});
    const baseline = fail.allocated_bytes - fail.freed_bytes;
    var failures: usize = 0;
    var succeeded = false;
    for (0..128) |n| {
        fail.fail_index = fail.alloc_index + n;
        var restored = MediaRooms.prepareRestore(fail.allocator(), &snapshot, &.{}) catch |err| {
            fail.fail_index = std.math.maxInt(usize);
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expectEqual(baseline, fail.allocated_bytes - fail.freed_bytes);
            try snapshot.validate();
            try testing.expectEqual(@as(u32, 1), rooms.rooms.count());
            failures += 1;
            continue;
        };
        fail.fail_index = std.math.maxInt(usize);
        try testing.expect(restored.isParticipant("#oom", "alice"));
        restored.deinit();
        try testing.expectEqual(baseline, fail.allocated_bytes - fail.freed_bytes);
        succeeded = true;
        break;
    }
    try testing.expect(succeeded and failures >= 3);
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

test "GAP-V6 speaking queue keeps raise order and drops on leave" {
    var m = MediaRooms.init(testing.allocator);
    defer m.deinit();
    try m.join("#c", "alice", .voice);
    try m.join("#c", "bob", .voice);
    try m.join("#c", "carol", .voice);
    try m.setHand("#c", "alice", true);
    try m.setHand("#c", "alice", true);
    try m.setHand("#c", "bob", true);
    try m.setHand("#c", "carol", true);
    var names: [8][]const u8 = undefined;
    try testing.expectEqual(@as(usize, 3), m.copySpeakQueue("#c", &names));
    try testing.expectEqualStrings("alice", names[0]);
    try testing.expectEqualStrings("bob", names[1]);
    try testing.expectEqualStrings("carol", names[2]);
    try m.setPosition("#c", "alice", .{ .x = 120, .y = -45 });
    try testing.expectEqual(Position{ .x = 120, .y = -45 }, m.positionOf("#c", "alice"));
    try m.setHand("#c", "alice", false);
    try testing.expectEqual(@as(usize, 2), m.copySpeakQueue("#c", &names));
    try testing.expectEqualStrings("bob", names[0]);
    try testing.expectEqualStrings("carol", names[1]);
    try testing.expect(m.leaveAll("#c", "bob"));
    try testing.expectEqual(@as(usize, 1), m.copySpeakQueue("#c", &names));
    try testing.expectEqualStrings("carol", names[0]);
    try testing.expect(m.leaveAll("#c", "alice"));
    try testing.expect(m.leaveAll("#c", "carol"));
    try testing.expectEqual(@as(usize, 0), m.copySpeakQueue("#c", &names));
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

fn validateProfile(profile: CallProfile) PreparedError!void {
    if (profile.codec_count > max_profile_codecs) return error.InvalidProfile;
}
fn profileEqual(a: ?CallProfile, b: ?CallProfile) bool {
    if (a == null or b == null) return a == null and b == null;
    return a.?.eql(b.?);
}
const MapState = struct { metadata: usize, count: u32, capacity: u32 };
fn mapState(map: anytype) MapState {
    return .{ .metadata = if (map.unmanaged.metadata) |ptr| @intFromPtr(ptr) else 0, .count = map.count(), .capacity = map.capacity() };
}
const ProfilePlan = struct {
    owner: *MediaRooms,
    revision: u64,
    keys: [2]PhysicalProfileKey,
    count: u8,
    channel: []u8 = &.{},
    display_nick: [64]u8 = @splat(0),
    display_len: u8 = 0,
    old: [2]?CallProfile = .{ null, null },
    old_call: ?CallProfile,
    old_call_key: usize,
    shared: ?CallProfile,
    advertised: CallProfile,
    calls_state: MapState,
    physical_state: MapState,
    new_call_key: ?[]u8 = null,
    call_growth: ?ChannelMap(CallProfile) = null,
    physical_growth: ?std.AutoHashMap(PhysicalProfileKey, CallProfile) = null,
    validated_domain: ?*routing.Domain = null,
    validated_scope: u64 = 0,
    committed: bool = false,
};
fn profilePlan(candidate: *PreparedProfiles) *ProfilePlan {
    return @ptrCast(@alignCast(candidate));
}

pub const PreparedProfiles = opaque {
    pub fn validateLocked(self: *PreparedProfiles, domain: *routing.Domain, scope: *const routing.Locked, offers: *routing.PreparedOffers) PreparedError!void {
        const serial = try domain.scopeSerial(scope);
        const plan = profilePlan(self);
        const owner = plan.owner;
        try offers.requireKeysLocked(domain, scope, plan.channel, plan.keys[0..plan.count]);
        if (plan.committed or owner.transport_revision != plan.revision or !std.meta.eql(plan.calls_state, mapState(owner.profiles)) or !std.meta.eql(plan.physical_state, mapState(owner.physical_profiles)) or !profileEqual(plan.old_call, owner.profiles.get(plan.channel))) return error.StaleCandidate;
        const current_key = if (owner.profiles.getEntry(plan.channel)) |entry| @intFromPtr(entry.key_ptr.*.ptr) else 0;
        if (current_key != plan.old_call_key) return error.StaleCandidate;
        for (plan.keys[0..plan.count], 0..) |key, n| {
            if (!profileEqual(plan.old[n], owner.physical_profiles.get(key))) return error.StaleCandidate;
        }
        plan.validated_domain = domain;
        plan.validated_scope = serial;
    }

    pub fn commitLocked(self: *PreparedProfiles, domain: *routing.Domain, scope: *const routing.Locked) void {
        const serial = domain.scopeSerial(scope) catch @panic("invalid profile publication cut");
        const plan = profilePlan(self);
        const owner = plan.owner;
        std.debug.assert(!plan.committed and plan.validated_domain == domain and plan.validated_scope == serial and owner.transport_revision == plan.revision);
        if (plan.physical_growth) |*replacement| {
            var it = owner.physical_profiles.iterator();
            while (it.next()) |entry| replacement.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
            std.mem.swap(@TypeOf(owner.physical_profiles), &owner.physical_profiles, replacement);
        }
        if (plan.call_growth) |*replacement| {
            var it = owner.profiles.iterator();
            while (it.next()) |entry| replacement.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
            std.mem.swap(@TypeOf(owner.profiles), &owner.profiles, replacement);
        }
        for (plan.keys[0..plan.count]) |key| owner.physical_profiles.putAssumeCapacity(key, plan.advertised);
        if (plan.shared) |profile| {
            if (plan.new_call_key) |key| {
                owner.profiles.putAssumeCapacity(key, profile);
                plan.new_call_key = null;
            } else owner.profiles.getPtr(plan.channel).?.* = profile;
        }
        owner.transport_revision += 1;
        plan.committed = true;
    }

    /// All owned cleanup is after the Domain cut. Retired map metadata is freed
    /// here, without freeing the OLD keys still retained by the live owner.
    pub fn deinit(self: *PreparedProfiles) void {
        const plan = profilePlan(self);
        const allocator = plan.owner.allocator;
        if (plan.physical_growth) |*map| map.deinit();
        if (plan.call_growth) |*map| map.deinit();
        if (plan.new_call_key) |key| allocator.free(key);
        allocator.free(plan.channel);
        allocator.destroy(plan);
    }
};

const SharedProfilePlan = struct {
    owner: *MediaRooms,
    revision: u64,
    old: ?CallProfile,
    old_key: usize,
    state: MapState,
    agreed: CallProfile,
    channel: []u8 = &.{},
    new_key: ?[]u8 = null,
    growth: ?ChannelMap(CallProfile) = null,
    validated_domain: ?*routing.Domain = null,
    validated_scope: u64 = 0,
    committed: bool = false,
};
fn sharedProfilePlan(candidate: *PreparedSharedProfile) *SharedProfilePlan {
    return @ptrCast(@alignCast(candidate));
}
pub const PreparedSharedProfile = opaque {
    pub fn validateLocked(self: *PreparedSharedProfile, domain: *routing.Domain, scope: *const routing.Locked, expected_agreed: CallProfile) PreparedError!void {
        const serial = try domain.scopeSerial(scope);
        const plan = sharedProfilePlan(self);
        const owner = plan.owner;
        if (!plan.agreed.eql(expected_agreed)) return error.InvalidProfile;
        if (plan.committed or owner.transport_revision != plan.revision or !std.meta.eql(plan.state, mapState(owner.profiles)) or !profileEqual(plan.old, owner.profiles.get(plan.channel))) return error.StaleCandidate;
        const key = if (owner.profiles.getEntry(plan.channel)) |entry| @intFromPtr(entry.key_ptr.*.ptr) else 0;
        if (key != plan.old_key) return error.StaleCandidate;
        plan.validated_domain = domain;
        plan.validated_scope = serial;
    }
    pub fn commitLocked(self: *PreparedSharedProfile, domain: *routing.Domain, scope: *const routing.Locked) void {
        const serial = domain.scopeSerial(scope) catch @panic("invalid shared profile publication cut");
        const plan = sharedProfilePlan(self);
        const owner = plan.owner;
        std.debug.assert(!plan.committed and plan.validated_domain == domain and plan.validated_scope == serial and owner.transport_revision == plan.revision);
        if (plan.growth) |*replacement| {
            var it = owner.profiles.iterator();
            while (it.next()) |entry| replacement.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
            std.mem.swap(@TypeOf(owner.profiles), &owner.profiles, replacement);
        }
        if (plan.new_key) |key| {
            owner.profiles.putAssumeCapacity(key, plan.agreed);
            plan.new_key = null;
        } else owner.profiles.getPtr(plan.channel).?.* = plan.agreed;
        owner.transport_revision += 1;
        plan.committed = true;
    }
    pub fn deinit(self: *PreparedSharedProfile) void {
        const plan = sharedProfilePlan(self);
        const allocator = plan.owner.allocator;
        if (plan.growth) |*map| map.deinit();
        if (plan.new_key) |key| allocator.free(key);
        allocator.free(plan.channel);
        allocator.destroy(plan);
    }
};

const JoinPlan = struct {
    owner: *MediaRooms,
    membership: routing.MembershipPreview,
    member_key: PhysicalMemberKey,
    old_member: ?PhysicalMember,
    next_member: PhysicalMember,
    members_state: MapState,
    member_growth: ?PhysicalMemberMap = null,
    revision: u64,
    rooms_state: MapState,
    channel: []u8 = &.{},
    old_room: ?*Room,
    old_key: usize,
    old_snapshot: Room.Snapshot,
    replacement: ?*Room = null,
    new_key: ?[]u8 = null,
    growth: ?RoomMap = null,
    validated_domain: ?*routing.Domain = null,
    validated_scope: u64 = 0,
    committed: bool = false,
};
fn joinPlan(candidate: *PreparedJoin) *JoinPlan {
    return @ptrCast(@alignCast(candidate));
}
pub const PreparedJoin = opaque {
    pub fn validateLocked(self: *PreparedJoin, domain: *routing.Domain, scope: *const routing.Locked, membership: *routing.PreparedMembership) PreparedError!void {
        const serial = try domain.scopeSerial(scope);
        const plan = joinPlan(self);
        const owner = plan.owner;
        try membership.requireJoinLocked(domain, scope, plan.channel, plan.membership);
        if (plan.committed or owner.transport_revision != plan.revision or !std.meta.eql(mapState(owner.rooms), plan.rooms_state) or !std.meta.eql(mapState(owner.physical_members), plan.members_state) or !std.meta.eql(owner.physical_members.get(plan.member_key), plan.old_member)) return error.StaleCandidate;
        // Obtain the CURRENT row before reading. An expired OLD pointer is only
        // a locator to compare; it is never dereferenced after removal.
        const current = owner.rooms.get(plan.channel);
        const current_key = if (owner.rooms.getEntry(plan.channel)) |entry| @intFromPtr(entry.key_ptr.*.ptr) else 0;
        if (current != plan.old_room or current_key != plan.old_key) return error.StaleCandidate;
        const snapshot = if (current) |room_ptr| try room_ptr.capture() else Room.Snapshot{};
        if (!std.meta.eql(snapshot, plan.old_snapshot)) return error.StaleCandidate;
        plan.validated_domain = domain;
        plan.validated_scope = serial;
    }
    pub fn commitLocked(self: *PreparedJoin, domain: *routing.Domain, scope: *const routing.Locked) void {
        const serial = domain.scopeSerial(scope) catch @panic("invalid room JOIN publication cut");
        const plan = joinPlan(self);
        const owner = plan.owner;
        std.debug.assert(!plan.committed and plan.validated_domain == domain and plan.validated_scope == serial and owner.transport_revision == plan.revision);
        if (plan.growth) |*replacement| {
            var it = owner.rooms.iterator();
            while (it.next()) |entry| replacement.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
            std.mem.swap(@TypeOf(owner.rooms), &owner.rooms, replacement);
        }
        if (plan.member_growth) |*replacement| {
            var it = owner.physical_members.iterator();
            while (it.next()) |entry| replacement.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
            std.mem.swap(PhysicalMemberMap, &owner.physical_members, replacement);
        }
        owner.physical_members.putAssumeCapacity(plan.member_key, plan.next_member);
        const final_room = plan.replacement.?;
        if (plan.new_key) |key| {
            owner.rooms.putAssumeCapacity(key, final_room);
            plan.new_key = null;
        } else owner.rooms.getPtr(plan.channel).?.* = final_room;
        // Retain replaced heap room until after Domain unlock. No allocator
        // callback occurs during the authority/output publication cut.
        plan.replacement = plan.old_room;
        owner.transport_revision += 1;
        plan.committed = true;
    }
    pub fn deinit(self: *PreparedJoin) void {
        const plan = joinPlan(self);
        const allocator = plan.owner.allocator;
        if (plan.member_growth) |*map| map.deinit();
        if (plan.growth) |*map| map.deinit();
        if (plan.replacement) |room_ptr| allocator.destroy(room_ptr);
        if (plan.new_key) |key| allocator.free(key);
        allocator.free(plan.channel);
        allocator.destroy(plan);
    }
};

const JoinedProfileTest = struct {
    domain: *routing.Domain,
    offer: *routing.PreparedOffers,
    profile: *PreparedProfiles,
    fn run(scope: *routing.Locked, ctx: @This()) PreparedError!void {
        try ctx.offer.validateLocked(ctx.domain, scope);
        try ctx.profile.validateLocked(ctx.domain, scope, ctx.offer);
        ctx.profile.commitLocked(ctx.domain, scope);
        ctx.offer.commitLocked(ctx.domain, scope);
    }
};
const JoinedRoomTest = struct {
    domain: *routing.Domain,
    membership: *routing.PreparedMembership,
    room: *PreparedJoin,
    fn run(scope: *routing.Locked, ctx: @This()) PreparedError!void {
        try ctx.membership.validateLocked(ctx.domain, scope);
        try ctx.room.validateLocked(ctx.domain, scope, ctx.membership);
        ctx.room.commitLocked(ctx.domain, scope);
        ctx.membership.commitLocked(ctx.domain, scope);
    }
};
const RevokeRoutingTest = struct {
    domain: *routing.Domain,
    call: routing.CallId,
    client: routing.ClientId,
    fn run(scope: *routing.Locked, ctx: @This()) routing.Error!void {
        try ctx.domain.revokeOffersLocked(scope, ctx.call, ctx.client);
        try ctx.domain.revokeMembershipLocked(scope, ctx.call, ctx.client);
    }
};
fn testProfile() CallProfile {
    var profile = CallProfile{};
    profile.codecs[0] = .{ .tag = .cadencevox, .clock_rate = 48000, .params = 0 };
    profile.codec_count = 1;
    return profile;
}
fn profileKeys(preview: routing.OfferPreview) [2]PhysicalProfileKey {
    var keys: [2]PhysicalProfileKey = @splat(std.mem.zeroes(PhysicalProfileKey));
    for (preview.endpoints[0..preview.count], 0..) |row, n| keys[n] = .{ .call = preview.call, .client = row.reference.offering_client, .leg = row.reference.endpoint.leg };
    return keys;
}
test "prepared physical profiles isolate sibling attachments and retain existing call key" {
    var rooms = MediaRooms.init(testing.allocator);
    defer rooms.deinit();
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("unclosed test source");
    const a = routing.ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const b = routing.ClientId{ .shard = 0, .slot = 1, .gen = 0 };
    const offer_a = try domain.prepareOffers("#c", a, &.{ .{ .leg = .native, .mode = .legacy_group }, .{ .leg = .webrtc, .mode = .dtls_required } });
    const preview_a = offer_a.preview();
    const keys_a = profileKeys(preview_a);
    const profile_a = try rooms.prepareTransportProfiles(keys_a[0..2], "#c", "same", testProfile(), testProfile());
    try domain.withLocked(JoinedProfileTest{ .domain = domain, .offer = offer_a, .profile = profile_a }, JoinedProfileTest.run);
    profile_a.deinit();
    offer_a.deinit();
    const original_key = @intFromPtr(rooms.profiles.getEntry("#c").?.key_ptr.*.ptr);
    var distinct = testProfile();
    distinct.fec = .{ .scheme = .rs_block, .redundancy = 1 };
    const offer_b = try domain.prepareOffers("#c", b, &.{.{ .leg = .webrtc, .mode = .dtls_required }});
    const keys_b = profileKeys(offer_b.preview());
    const profile_b = try rooms.prepareTransportProfiles(keys_b[0..1], "#c", "same", distinct, distinct);
    try domain.withLocked(JoinedProfileTest{ .domain = domain, .offer = offer_b, .profile = profile_b }, JoinedProfileTest.run);
    profile_b.deinit();
    offer_b.deinit();
    try testing.expectEqual(original_key, @intFromPtr(rooms.profiles.getEntry("#c").?.key_ptr.*.ptr));
    try testing.expect(profileEqual(testProfile(), rooms.physicalProfileOf(keys_a[0])));
    try testing.expect(profileEqual(testProfile(), rooms.physicalProfileOf(keys_a[1])));
    try testing.expect(profileEqual(distinct, rooms.physicalProfileOf(keys_b[0])));
    try domain.withLocked(RevokeRoutingTest{ .domain = domain, .call = preview_a.call, .client = a }, RevokeRoutingTest.run);
    try domain.withLocked(RevokeRoutingTest{ .domain = domain, .call = preview_a.call, .client = b }, RevokeRoutingTest.run);
}

test "prepared room JOIN publishes only with exact source-issued membership" {
    var rooms = MediaRooms.init(testing.allocator);
    defer rooms.deinit();
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("unclosed test source");
    const client_id = routing.ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const membership = try domain.prepareMembership("#j", client_id, 1);
    const preview = membership.preview();
    const candidate = try rooms.prepareJoin(preview, "#j", "same", .voice);
    try testing.expect(rooms.room("#j") == null);
    try domain.withLocked(JoinedRoomTest{ .domain = domain, .membership = membership, .room = candidate }, JoinedRoomTest.run);
    candidate.deinit();
    membership.deinit();
    try testing.expect(rooms.isParticipant("#j", "same"));
    try testing.expect(rooms.isParticipant("#J", "same"));
    try testing.expect(!rooms.isParticipant("#J", "other"));
    try testing.expectEqual(@as(u32, 1), rooms.rooms.count());
    try domain.withLocked(RevokeRoutingTest{ .domain = domain, .call = preview.call, .client = client_id }, RevokeRoutingTest.run);
}
fn preparedRoomOom(allocator: std.mem.Allocator) !void {
    var rooms = MediaRooms.init(testing.allocator);
    defer rooms.deinit();
    try rooms.join("#J", "old", .voice);
    const original_room = rooms.room("#j").?;
    const original = try original_room.capture();
    const table = mapState(rooms.rooms);
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("unclosed candidate source");
    const membership = try domain.prepareMembership("#j", .{ .shard = 0, .slot = 0, .gen = 0 }, 1);
    defer membership.deinit();
    rooms.allocator = allocator;
    defer rooms.allocator = testing.allocator;
    const plan = rooms.prepareJoin(membership.preview(), "#j", "new", .voice) catch |err| {
        try testing.expectEqual(original_room, rooms.room("#j").?);
        try testing.expectEqualDeep(original, try original_room.capture());
        try testing.expectEqualDeep(table, mapState(rooms.rooms));
        try testing.expectEqual(@as(u64, 1), rooms.transport_revision);
        return err;
    };
    plan.deinit();
    try testing.expectEqualDeep(original, try original_room.capture());
    try testing.expectEqualDeep(table, mapState(rooms.rooms));
}
test "prepared room JOIN every allocation failure preserves OLD heap room and backing" {
    try testing.checkAllAllocationFailures(testing.allocator, preparedRoomOom, .{});
}

fn Stored(comptime T: type) type {
    return struct { key: []const u8, value: T, digest: [32]u8 };
}
fn storedDigest(comptime T: type, key: []const u8, value: T) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(key);
    if (T == []u8) {
        std.hash.autoHash(&hash, @intFromPtr(value.ptr));
        std.hash.autoHash(&hash, value.len);
        hash.update(value);
    } else if (T == CallProfile) {
        std.hash.autoHash(&hash, value.codec_count);
        std.hash.autoHash(&hash, value.fec);
        if (value.codec_count <= max_profile_codecs) for (value.slice()) |codec| std.hash.autoHash(&hash, codec);
    } else if (T == Recording) {
        std.hash.autoHash(&hash, value.by_len);
        std.hash.autoHash(&hash, value.active);
        if (value.by_len <= value.by_buf.len) hash.update(value.by_buf[0..value.by_len]);
    } else if (T == std.ArrayList([]u8)) {
        std.hash.autoHash(&hash, @intFromPtr(value.items.ptr));
        std.hash.autoHash(&hash, value.items.len);
        std.hash.autoHash(&hash, value.capacity);
        for (value.items) |name| {
            std.hash.autoHash(&hash, @intFromPtr(name.ptr));
            std.hash.autoHash(&hash, name.len);
            hash.update(name);
        }
    } else if (T != void) std.hash.autoHash(&hash, value);
    return hash.finalResult();
}
fn captureStored(comptime T: type, map: anytype, key: []const u8) ?Stored(T) {
    const actual = map.getEntry(key) orelse return null;
    return .{ .key = actual.key_ptr.*, .value = actual.value_ptr.*, .digest = storedDigest(T, actual.key_ptr.*, actual.value_ptr.*) };
}
fn validateStored(comptime T: type, map: anytype, lookup: []const u8, old: ?Stored(T)) bool {
    const actual = map.getEntry(lookup);
    if (old == null) return actual == null;
    const row = actual orelse return false;
    // Never dereference an expired OLD payload before proving its current
    // source locator. Dynamic payload bytes are hashed from CURRENT ownership.
    return row.key_ptr.*.ptr == old.?.key.ptr and row.key_ptr.*.len == old.?.key.len and std.mem.eql(u8, &old.?.digest, &storedDigest(T, row.key_ptr.*, row.value_ptr.*));
}
const RoomDeparturePlan = struct {
    owner: *MediaRooms,
    key: PhysicalMemberKey,
    revision: u64,
    terminal: bool,
    batch_part: bool,
    old_member: ?PhysicalMember,
    members_state: MapState,
    physical_state: MapState,
    old_profiles: [2]?CallProfile = .{ null, null },
    channel: []u8 = &.{},
    member_lookup: []u8 = &.{},
    old_room: ?*Room,
    old_room_key: ?[]const u8,
    old_snapshot: Room.Snapshot,
    replacement: ?*Room = null,
    drop_room: bool,
    clear_display: bool,
    clear_shared: bool,
    affected_display: ?media.ParticipantId,
    room_update: bool,
    final_room_empty: bool,
    breakout: ?Stored([]u8) = null,
    position: ?Stored(Position) = null,
    hand: ?Stored(void) = null,
    participant_profile: ?Stored(CallProfile) = null,
    consent: ?Stored(void) = null,
    quality: ?Stored(Quality) = null,
    shared: ?Stored(CallProfile) = null,
    recording: ?Stored(Recording) = null,
    queue: ?Stored(std.ArrayList([]u8)) = null,
    retired_speaker: ?[]u8 = null,
    queue_removed: bool = false,
    retired_room: ?*Room = null,
    validated_domain: ?*routing.Domain = null,
    validated_scope: u64 = 0,
    committed: bool = false,
};
fn roomDeparture(candidate: *PreparedRoomDeparture) *RoomDeparturePlan {
    return @ptrCast(@alignCast(candidate));
}
/// Immutable preparation observations from the source-owned departure plan.
/// Both slices borrow the candidate until deinit; they are not a current-state
/// proof. The graph owner copies any output metadata before cleanup and joins
/// the actual candidate through validateLocked before publishing its effects.
pub const DepartureTransition = struct {
    channel: []const u8,
    /// Empty when neither a protected physical member nor an explicitly
    /// censused legacy owner changes display geometry in this departure.
    display: []const u8,
    had_member: bool,
    display_remains: bool,
    drops_room: bool,
};
fn departureTransition(plan: *const RoomDeparturePlan) DepartureTransition {
    return .{
        .channel = plan.channel,
        // Borrow the plan-owned display payload, never an iterator temporary.
        .display = if (plan.affected_display) |*display| (if (plan.room_update) display.slice() else "") else "",
        .had_member = plan.room_update,
        .display_remains = plan.room_update and !plan.clear_display,
        .drops_room = plan.drop_room,
    };
}
pub const PreparedRoomDeparture = opaque {
    pub fn transition(self: *PreparedRoomDeparture) DepartureTransition {
        return departureTransition(roomDeparture(self));
    }
    pub fn validateLocked(self: *PreparedRoomDeparture, domain: *routing.Domain, scope: *const routing.Locked, departure: *routing.PreparedDeparture) PreparedError!void {
        const serial = try domain.scopeSerial(scope);
        const plan = roomDeparture(self);
        const owner = plan.owner;
        try departure.requireOwnerLocked(domain, scope, .{ .call = plan.key.call, .client = plan.key.client, .leg = .native });
        try departure.requireChannelLocked(domain, scope, plan.channel);
        if (plan.terminal) try domain.requireTerminalLocked(scope);
        if (plan.committed or departure.isTerminal() != plan.terminal or owner.transport_revision != plan.revision or !std.meta.eql(plan.members_state, mapState(owner.physical_members)) or !std.meta.eql(plan.physical_state, mapState(owner.physical_profiles)) or !std.meta.eql(plan.old_member, owner.physical_members.get(plan.key))) return error.StaleCandidate;
        const room_now = owner.rooms.get(plan.channel);
        const room_key = if (owner.rooms.getEntry(plan.channel)) |entry| entry.key_ptr.* else null;
        if (room_now != plan.old_room or (room_key == null) != (plan.old_room_key == null)) return error.StaleCandidate;
        if (room_key) |key| if (key.ptr != plan.old_room_key.?.ptr or key.len != plan.old_room_key.?.len) return error.StaleCandidate;
        const snapshot = if (room_now) |row| try row.capture() else Room.Snapshot{};
        if (!std.meta.eql(snapshot, plan.old_snapshot)) return error.StaleCandidate;
        for ([_]routing.Leg{ .native, .webrtc }, 0..) |leg, n| if (!profileEqual(plan.old_profiles[n], owner.physical_profiles.get(.{ .call = plan.key.call, .client = plan.key.client, .leg = leg }))) return error.StaleCandidate;
        if (plan.clear_shared != (departure.removesCall() and plan.final_room_empty)) return error.StaleCandidate;
        if (plan.clear_display) {
            if (!validateStored([]u8, owner.breakouts, plan.member_lookup, plan.breakout) or !validateStored(Position, owner.positions, plan.member_lookup, plan.position) or !validateStored(void, owner.hands, plan.member_lookup, plan.hand) or !validateStored(CallProfile, owner.participant_profiles, plan.member_lookup, plan.participant_profile) or !validateStored(void, owner.consents, plan.member_lookup, plan.consent) or !validateStored(Quality, owner.qualities, plan.member_lookup, plan.quality)) return error.StaleCandidate;
        }
        if (!validateStored(std.ArrayList([]u8), owner.queues, plan.channel, plan.queue)) return error.StaleCandidate;
        if (plan.drop_room and !validateStored(Recording, owner.recordings, plan.channel, plan.recording)) return error.StaleCandidate;
        if (plan.clear_shared and !validateStored(CallProfile, owner.profiles, plan.channel, plan.shared)) return error.StaleCandidate;
        plan.validated_domain = domain;
        plan.validated_scope = serial;
    }
    pub fn commitLocked(self: *PreparedRoomDeparture, domain: *routing.Domain, scope: *const routing.Locked) void {
        const serial = domain.scopeSerial(scope) catch @panic("invalid physical Room departure");
        const plan = roomDeparture(self);
        const owner = plan.owner;
        std.debug.assert(!plan.committed and plan.validated_domain == domain and plan.validated_scope == serial and owner.transport_revision == plan.revision);
        std.debug.assert(!plan.batch_part);
        applyRoomDeparture(plan);
        if (!plan.terminal) owner.transport_revision += 1;
    }
    pub fn deinit(self: *PreparedRoomDeparture) void {
        const plan = roomDeparture(self);
        const a = plan.owner.allocator;
        if (plan.committed) {
            if (plan.clear_display) {
                if (plan.breakout) |row| {
                    a.free(row.value);
                    a.free(row.key);
                }
                inline for (.{ plan.position, plan.hand, plan.participant_profile, plan.consent, plan.quality }) |old| if (old) |row| a.free(row.key);
            }
            if (plan.clear_shared) if (plan.shared) |row| a.free(row.key);
            if (plan.drop_room) {
                if (plan.old_room_key) |key| a.free(key);
                if (plan.recording) |row| a.free(row.key);
            }
            if (plan.queue_removed) if (plan.queue) |row| {
                for (row.value.items) |name| a.free(name);
                var list = row.value;
                list.deinit(a);
                a.free(row.key);
            };
            if (plan.retired_speaker) |name| a.free(name);
            if (plan.retired_room) |room_ptr| a.destroy(room_ptr);
        }
        if (plan.replacement) |room_ptr| a.destroy(room_ptr);
        a.free(plan.member_lookup);
        a.free(plan.channel);
        a.destroy(plan);
    }
};

const RoomDepartureTestCut = struct {
    domain: *routing.Domain,
    departure: *routing.PreparedDeparture,
    room: *PreparedRoomDeparture,
    fn run(scope: *routing.Locked, ctx: @This()) PreparedError!void {
        try ctx.departure.validateLocked(ctx.domain, scope);
        try ctx.room.validateLocked(ctx.domain, scope, ctx.departure);
        ctx.room.commitLocked(ctx.domain, scope);
        ctx.departure.commitLocked(ctx.domain, scope);
    }
};
fn publishRoomJoinTest(domain: *routing.Domain, rooms: *MediaRooms, id: routing.ClientId, kind: MediaKind) !routing.CallId {
    const membership = try domain.prepareMembership("#Departure", id, @as(u8, 1) << @backingInt(kind));
    defer membership.deinit();
    const plan = try rooms.prepareJoin(membership.preview(), "#departure", "same", kind);
    defer plan.deinit();
    const Cut = struct {
        domain: *routing.Domain,
        membership: *routing.PreparedMembership,
        room: *PreparedJoin,
        fn run(scope: *routing.Locked, ctx: @This()) PreparedError!void {
            try ctx.membership.validateLocked(ctx.domain, scope);
            try ctx.room.validateLocked(ctx.domain, scope, ctx.membership);
            ctx.room.commitLocked(ctx.domain, scope);
            ctx.membership.commitLocked(ctx.domain, scope);
        }
    };
    try domain.withLocked(Cut{ .domain = domain, .membership = membership, .room = plan }, Cut.run);
    return membership.preview().call;
}
fn cleanupRoomDomainTest(domain: *routing.Domain, call: ?routing.CallId) void {
    const known = call orelse return;
    const Cut = struct {
        domain: *routing.Domain,
        call: routing.CallId,
        fn run(scope: *routing.Locked, ctx: @This()) routing.Error!void {
            for ([_]routing.ClientId{ .{ .shard = 0, .slot = 0, .gen = 0 }, .{ .shard = 0, .slot = 1, .gen = 0 } }) |id| try ctx.domain.revokeMembershipLocked(scope, ctx.call, id);
        }
    };
    domain.withLocked(Cut{ .domain = domain, .call = known }, Cut.run) catch @panic("Room fixture Domain cleanup");
}
test "prepared physical Room departure preserves same-display sibling kinds and retires every last-member payload" {
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("Room departure Domain rows");
    var call: ?routing.CallId = null;
    defer cleanupRoomDomainTest(domain, call);
    var rooms = MediaRooms.init(testing.allocator);
    defer rooms.deinit();
    const a = routing.ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const b = routing.ClientId{ .shard = 0, .slot = 1, .gen = 0 };
    call = try publishRoomJoinTest(domain, &rooms, a, .voice);
    _ = try publishRoomJoinTest(domain, &rooms, b, .video);
    try rooms.setBreakout("#departure", "same", "retained");
    try rooms.setPosition("#departure", "same", .{ .x = 7, .y = 11 });
    try rooms.setHand("#departure", "same", true);
    try testing.expect(try rooms.setConsent("#departure", "same", true));
    try testing.expect(try rooms.setQuality("#departure", "same", .{ .loss_pct = 3, .rtt_ms = 4, .spatial = 1, .bitrate_kbps = 500 }));
    _ = try rooms.startRecording("#departure", "same");
    const advertised = testProfile();
    try rooms.setParticipantProfile("#departure", "same", advertised.slice(), advertised.fec);
    try rooms.setProfile("#departure", advertised.slice(), advertised.fec);
    // setProfile's historical mutation above is setup, not a claim of prepared
    // profile atomicity. Install its display row afterward for full retirement.
    try rooms.setParticipantProfile("#departure", "same", advertised.slice(), advertised.fec);
    {
        const departure = try domain.prepareDeparture(call.?, a);
        defer departure.deinit();
        const candidate = try rooms.prepareDeparture(departure, "#DEPARTURE");
        defer candidate.deinit();
        try domain.withLocked(RoomDepartureTestCut{ .domain = domain, .departure = departure, .room = candidate }, RoomDepartureTestCut.run);
    }
    try testing.expectEqual(@as(u32, 1), rooms.physical_members.count());
    const row = rooms.rooms.get("#departure").?.participant(try media.ParticipantId.init("same")).?;
    try testing.expect(!row.joined.contains(.voice) and row.joined.contains(.video));
    try testing.expectEqualStrings("retained", rooms.breakoutOf("#departure", "same"));
    try testing.expect(rooms.handRaised("#departure", "same"));
    try testing.expect(rooms.transportProfileOf("#DEPARTURE") != null);
    {
        const departure = try domain.prepareDeparture(call.?, b);
        defer departure.deinit();
        const candidate = try rooms.prepareDeparture(departure, "#departure");
        defer candidate.deinit();
        try domain.withLocked(RoomDepartureTestCut{ .domain = domain, .departure = departure, .room = candidate }, RoomDepartureTestCut.run);
    }
    try testing.expectEqual(@as(u32, 0), rooms.physical_members.count());
    inline for (.{ rooms.rooms, rooms.breakouts, rooms.positions, rooms.hands, rooms.participant_profiles, rooms.consents, rooms.qualities, rooms.profiles, rooms.recordings, rooms.queues }) |map| try testing.expectEqual(@as(u32, 0), map.count());
}
fn roomDepartureOom(allocator: std.mem.Allocator) !void {
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("Room OOM Domain rows");
    var call: ?routing.CallId = null;
    defer cleanupRoomDomainTest(domain, call);
    var rooms = MediaRooms.init(allocator);
    defer rooms.deinit();
    const a = routing.ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    call = try publishRoomJoinTest(domain, &rooms, a, .voice);
    try rooms.setBreakout("#DEPARTURE", "same", "owned");
    try rooms.setHand("#DEPARTURE", "same", true);
    const profile = testProfile();
    try rooms.setProfile("#DEPARTURE", profile.slice(), profile.fec);
    try rooms.setPosition("#DEPARTURE", "same", .{ .x = 7, .y = -4 });
    try rooms.setParticipantProfile("#DEPARTURE", "same", profile.slice(), profile.fec);
    try testing.expect(try rooms.setConsent("#DEPARTURE", "same", true));
    try testing.expect(try rooms.setQuality("#DEPARTURE", "same", .{ .loss_pct = 3 }));
    try testing.expect(try rooms.startRecording("#DEPARTURE", "same"));
    const original_room = rooms.rooms.get("#departure").?;
    const original = try original_room.capture();
    const members = mapState(rooms.physical_members);
    const room_table = mapState(rooms.rooms);
    const revision = rooms.transport_revision;
    const departure = try domain.prepareDeparture(call.?, a);
    defer departure.deinit();
    const candidate = rooms.prepareDeparture(departure, "#departure") catch |err| {
        try testing.expect(original_room == rooms.rooms.get("#departure").?);
        try testing.expectEqualDeep(original, try original_room.capture());
        try testing.expectEqualDeep(members, mapState(rooms.physical_members));
        try testing.expectEqualDeep(room_table, mapState(rooms.rooms));
        try testing.expectEqual(revision, rooms.transport_revision);
        try testing.expectEqualStrings("owned", rooms.breakoutOf("#departure", "same"));
        try testing.expect(rooms.handRaised("#departure", "same"));
        try testing.expect(rooms.hasConsent("#departure", "same"));
        try testing.expect(rooms.recordingOf("#departure").?.active);
        try testing.expect(rooms.profileOf("#departure").?.eql(profile));
        try testing.expect(rooms.participantProfileOf("#departure", "same").?.eql(profile));
        try testing.expectEqual(@as(u8, 3), rooms.qualityOf("#departure", "same").?.loss_pct);
        return err;
    };
    candidate.deinit();
    try testing.expect(original_room == rooms.rooms.get("#departure").?);
    try testing.expectEqualDeep(original, try original_room.capture());
}
test "prepared physical Room departure allocation failures retain original graph and payloads" {
    try testing.checkAllAllocationFailures(testing.allocator, roomDepartureOom, .{});
}

fn applyRoomDeparture(plan: *RoomDeparturePlan) void {
    const owner = plan.owner;
    _ = owner.physical_members.remove(plan.key);
    for ([_]routing.Leg{ .native, .webrtc }) |leg| _ = owner.physical_profiles.remove(.{ .call = plan.key.call, .client = plan.key.client, .leg = leg });
    if (plan.room_update) {
        if (plan.drop_room) _ = owner.rooms.remove(plan.channel) else {
            owner.rooms.getPtr(plan.channel).?.* = plan.replacement.?;
            plan.replacement = null;
        }
        plan.retired_room = plan.old_room;
    }
    if (plan.clear_display) {
        _ = owner.breakouts.remove(plan.member_lookup);
        _ = owner.positions.remove(plan.member_lookup);
        _ = owner.hands.remove(plan.member_lookup);
        _ = owner.participant_profiles.remove(plan.member_lookup);
        _ = owner.consents.remove(plan.member_lookup);
        _ = owner.qualities.remove(plan.member_lookup);
    }
    if (plan.clear_shared) _ = owner.profiles.remove(plan.channel);
    if (plan.drop_room) {
        _ = owner.recordings.remove(plan.channel);
        _ = owner.queues.remove(plan.channel);
        plan.queue_removed = plan.queue != null;
    } else if (plan.clear_display) {
        if (owner.queues.getPtr(plan.channel)) |queue| {
            const display = plan.affected_display.?.slice();
            for (queue.items, 0..) |name, n| if (std.mem.eql(u8, name, display)) {
                plan.retired_speaker = queue.orderedRemove(n);
                break;
            };
            if (queue.items.len == 0) {
                if (plan.queue) |*row| row.value = queue.*;
                _ = owner.queues.remove(plan.channel);
                plan.queue_removed = true;
            }
        }
    }
    plan.committed = true;
}
const RoomClientDeparturePlan = struct {
    owner: *MediaRooms,
    departure: *routing.PreparedClientDeparture,
    parts: []*PreparedRoomDeparture,
    revision: u64,
    validated_domain: ?*routing.Domain = null,
    validated_scope: u64 = 0,
    committed: bool = false,
};
fn roomClientDeparture(candidate: *PreparedRoomClientDeparture) *RoomClientDeparturePlan {
    return @ptrCast(@alignCast(candidate));
}
pub const PreparedRoomClientDeparture = opaque {
    pub fn count(self: *PreparedRoomClientDeparture) usize {
        return roomClientDeparture(self).parts.len;
    }
    /// Bounds are checked before touching a part. Observations borrow this
    /// complete candidate and retain the singleton view's validation contract.
    pub fn transition(self: *PreparedRoomClientDeparture, index: usize) PreparedError!DepartureTransition {
        const plan = roomClientDeparture(self);
        if (index >= plan.parts.len) return error.InvalidRequest;
        return plan.parts[index].transition();
    }
    pub fn validateLocked(self: *PreparedRoomClientDeparture, domain: *routing.Domain, scope: *const routing.Locked, departure: *routing.PreparedClientDeparture) PreparedError!void {
        const serial = try domain.scopeSerial(scope);
        const plan = roomClientDeparture(self);
        if (plan.departure != departure or plan.committed or plan.parts.len != departure.count() or plan.owner.transport_revision != plan.revision) return error.StaleCandidate;
        try departure.validateLocked(domain, scope);
        for (plan.parts, 0..) |part, n| {
            try departure.requirePartLocked(domain, scope, n, departure.part(n));
            const row = roomDeparture(part);
            if (!row.batch_part or row.revision != plan.revision) return error.StaleCandidate;
            try part.validateLocked(domain, scope, departure.part(n));
        }
        plan.validated_domain = domain;
        plan.validated_scope = serial;
    }
    pub fn commitLocked(self: *PreparedRoomClientDeparture, domain: *routing.Domain, scope: *const routing.Locked) void {
        const serial = domain.scopeSerial(scope) catch @panic("invalid complete Room departure cut");
        const plan = roomClientDeparture(self);
        std.debug.assert(!plan.committed and plan.validated_domain == domain and plan.validated_scope == serial and plan.owner.transport_revision == plan.revision);
        for (plan.parts) |part| {
            const row = roomDeparture(part);
            std.debug.assert(row.batch_part and !row.committed and row.validated_scope == serial);
            applyRoomDeparture(row);
        }
        if (plan.parts.len != 0 and !plan.departure.isTerminal()) plan.owner.transport_revision += 1;
        plan.committed = true;
    }
    pub fn deinit(self: *PreparedRoomClientDeparture) void {
        const plan = roomClientDeparture(self);
        const a = plan.owner.allocator;
        for (plan.parts) |part| part.deinit();
        a.free(plan.parts);
        a.destroy(plan);
    }
};

fn roomPreparedGrowthRetrySweep(profile: bool) !void {
    var fail = testing.FailingAllocator.init(testing.allocator, .{});
    var rooms = MediaRooms.init(fail.allocator());
    defer rooms.deinit();
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("Room growth retry source custody");
    const id = routing.ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const offers = try domain.prepareOffers("#retry", id, &.{ .{ .leg = .native, .mode = .legacy_group }, .{ .leg = .webrtc, .mode = .legacy_group } });
    defer offers.deinit();
    const preview = offers.preview();
    const keys = [_]routing.EndpointKey{ .{ .call = preview.call, .client = id, .leg = .native }, .{ .call = preview.call, .client = id, .leg = .webrtc } };
    const membership = try domain.prepareMembership("#retry", id, 1);
    defer membership.deinit();
    const old_rooms = mapState(rooms.rooms);
    const old_members = mapState(rooms.physical_members);
    const old_profiles = mapState(rooms.profiles);
    const old_physical = mapState(rooms.physical_profiles);
    const old_allocated = fail.allocated_bytes - fail.freed_bytes;
    var failures: usize = 0;
    var succeeded = false;
    for (0..32) |n| {
        fail.fail_index = fail.alloc_index + n;
        if (profile) {
            const plan = rooms.prepareTransportProfiles(&keys, "#retry", "same", testProfile(), testProfile()) catch |err| {
                fail.fail_index = std.math.maxInt(usize);
                try testing.expectEqual(error.OutOfMemory, err);
                try testing.expectEqual(old_allocated, fail.allocated_bytes - fail.freed_bytes);
                try testing.expectEqualDeep(old_profiles, mapState(rooms.profiles));
                try testing.expectEqualDeep(old_physical, mapState(rooms.physical_profiles));
                const retry = try rooms.prepareTransportProfiles(&keys, "#retry", "same", testProfile(), testProfile());
                retry.deinit();
                try std.testing.expectEqual(old_allocated, fail.allocated_bytes - fail.freed_bytes);
                failures += 1;
                continue;
            };
            fail.fail_index = std.math.maxInt(usize);
            plan.deinit();
        } else {
            const plan = rooms.prepareJoin(membership.preview(), "#retry", "same", .voice) catch |err| {
                fail.fail_index = std.math.maxInt(usize);
                try testing.expectEqual(error.OutOfMemory, err);
                try testing.expectEqual(old_allocated, fail.allocated_bytes - fail.freed_bytes);
                try testing.expectEqualDeep(old_rooms, mapState(rooms.rooms));
                try testing.expectEqualDeep(old_members, mapState(rooms.physical_members));
                const retry = try rooms.prepareJoin(membership.preview(), "#retry", "same", .voice);
                retry.deinit();
                try std.testing.expectEqual(old_allocated, fail.allocated_bytes - fail.freed_bytes);
                failures += 1;
                continue;
            };
            fail.fail_index = std.math.maxInt(usize);
            plan.deinit();
        }
        succeeded = true;
        break;
    }
    try testing.expectEqual(old_allocated, fail.allocated_bytes - fail.freed_bytes);
    try testing.expect(succeeded and failures >= 5);
    try testing.expectEqual(@as(u64, 1), rooms.transport_revision);
    try testing.expectEqualDeep(old_rooms, mapState(rooms.rooms));
    try testing.expectEqualDeep(old_members, mapState(rooms.physical_members));
    try testing.expectEqualDeep(old_profiles, mapState(rooms.profiles));
    try testing.expectEqualDeep(old_physical, mapState(rooms.physical_profiles));
}
test "prepared Room profiles and fresh JOIN every growth failure have exact OLD and same owner retry" {
    try roomPreparedGrowthRetrySweep(true);
    try roomPreparedGrowthRetrySweep(false);
}

test "prepared Room partial display departure every later lookup OOM frees replacement and retries" {
    var fail = testing.FailingAllocator.init(testing.allocator, .{});
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("partial Room departure source custody");
    var call: ?routing.CallId = null;
    defer cleanupRoomDomainTest(domain, call);
    var rooms = MediaRooms.init(fail.allocator());
    defer rooms.deinit();
    const a = routing.ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const b = routing.ClientId{ .shard = 0, .slot = 1, .gen = 0 };
    call = try publishRoomJoinTest(domain, &rooms, a, .voice);
    {
        const membership = try domain.prepareMembership("#departure", b, 1);
        defer membership.deinit();
        const candidate = try rooms.prepareJoin(membership.preview(), "#departure", "other", .voice);
        defer candidate.deinit();
        try domain.withLocked(JoinedRoomTest{ .domain = domain, .membership = membership, .room = candidate }, JoinedRoomTest.run);
    }
    try rooms.setBreakout("#departure", "same", "retained");
    const original_room = rooms.rooms.get("#departure").?;
    const original = try original_room.capture();
    const original_members = mapState(rooms.physical_members);
    const original_rooms = mapState(rooms.rooms);
    const revision = rooms.transport_revision;
    const departure = try domain.prepareDeparture(call.?, a);
    defer departure.deinit();
    const old_allocated = fail.allocated_bytes - fail.freed_bytes;
    var failures: usize = 0;
    var succeeded = false;
    for (0..32) |n| {
        fail.fail_index = fail.alloc_index + n;
        const candidate = rooms.prepareDeparture(departure, "#departure") catch |err| {
            fail.fail_index = std.math.maxInt(usize);
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expectEqual(old_allocated, fail.allocated_bytes - fail.freed_bytes);
            try testing.expectEqualDeep(original, try original_room.capture());
            try testing.expectEqualDeep(original_members, mapState(rooms.physical_members));
            try testing.expectEqualDeep(original_rooms, mapState(rooms.rooms));
            try testing.expectEqual(revision, rooms.transport_revision);
            try testing.expectEqualStrings("retained", rooms.breakoutOf("#departure", "same"));
            {
                const retry = try rooms.prepareDeparture(departure, "#departure");
                defer retry.deinit();
                try testing.expect(roomDeparture(retry).replacement != null and roomDeparture(retry).clear_display and !roomDeparture(retry).drop_room);
            }
            try std.testing.expectEqual(old_allocated, fail.allocated_bytes - fail.freed_bytes);
            failures += 1;
            continue;
        };
        {
            defer candidate.deinit();
            fail.fail_index = std.math.maxInt(usize);
            try testing.expect(roomDeparture(candidate).replacement != null and roomDeparture(candidate).clear_display and !roomDeparture(candidate).drop_room);
        }
        succeeded = true;
        break;
    }
    try testing.expectEqual(old_allocated, fail.allocated_bytes - fail.freed_bytes);
    try testing.expect(succeeded and failures >= 4);
    try testing.expectEqualDeep(original, try original_room.capture());
    try testing.expectEqual(revision, rooms.transport_revision);
}

test "call profile logical equality ignores independent unused storage and rejects initialized changes" {
    var a = CallProfile{ .codec_count = 1, .codecs = @splat(.{ .tag = .raw, .clock_rate = 7, .params = 9 }) };
    var b = CallProfile{ .codec_count = 1, .codecs = @splat(.{ .tag = .cadencevis, .clock_rate = 11, .params = 13 }) };
    a.codecs[0] = .{ .tag = .cadencevox, .clock_rate = 48000, .params = 0 };
    b.codecs[0] = a.codecs[0];
    try testing.expect(a.eql(b));
    try testing.expect(profileEqual(a, b));
    b.codecs[0].params = 1;
    try testing.expect(!a.eql(b));
    b.codecs[0] = a.codecs[0];
    b.fec.redundancy = 1;
    try testing.expect(!a.eql(b));
    b.fec = a.fec;
    b.codec_count = max_profile_codecs + 1;
    try testing.expect(!a.eql(b));
}

test "physical agreed kind projection reads initialized agreed codecs only" {
    var profile = testProfile();
    try std.testing.expectEqual(@as(u8, 1), try agreedKindBits(profile));
    for (profile.codecs[profile.codec_count..]) |*codec| codec.* = .{ .tag = .raw, .clock_rate = 9000, .params = 1 };
    try std.testing.expectEqual(@as(u8, 1), try agreedKindBits(profile));
    profile.codecs[0].tag = .cadencevis;
    try std.testing.expectEqual(@as(u8, 6), try agreedKindBits(profile));
    profile.codecs[0].tag = .raw;
    try std.testing.expectEqual(@as(u8, 7), try agreedKindBits(profile));
    profile.codec_count = 0;
    try std.testing.expectError(error.InvalidProfile, agreedKindBits(profile));
    profile.codec_count = max_profile_codecs + 1;
    try std.testing.expectError(error.InvalidProfile, agreedKindBits(profile));
}

test "physical shared public profile complete OOM rollback logical equality and retry without endpoints" {
    const domain = try routing.Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch @panic("shared profile fixture custody");
    const Cut = struct {
        domain: *routing.Domain,
        plan: *PreparedSharedProfile,
        profile: CallProfile,
        publish: bool,
        fn run(scope: *routing.Locked, ctx: @This()) !void {
            try ctx.plan.validateLocked(ctx.domain, scope, ctx.profile);
            if (ctx.publish) ctx.plan.commitLocked(ctx.domain, scope);
        }
    };
    var succeeded = false;
    var failures: usize = 0;
    for (0..16) |index| {
        var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var rooms = MediaRooms.init(fail.allocator());
        defer rooms.deinit();
        const old = mapState(rooms.profiles);
        const allocated = fail.allocated_bytes - fail.freed_bytes;
        fail.fail_index = fail.alloc_index + index;
        const candidate = rooms.prepareSharedProfile("#public", testProfile()) catch |err| {
            fail.fail_index = std.math.maxInt(usize);
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(allocated, fail.allocated_bytes - fail.freed_bytes);
            try std.testing.expectEqualDeep(old, mapState(rooms.profiles));
            try std.testing.expectEqual(@as(u64, 1), rooms.transport_revision);
            const retry = try rooms.prepareSharedProfile("#public", testProfile());
            defer retry.deinit();
            try domain.withLocked(Cut{ .domain = domain, .plan = retry, .profile = testProfile(), .publish = true }, Cut.run);
            try std.testing.expect(rooms.transportProfileOf("#public").?.eql(testProfile()));
            try std.testing.expectEqual(@as(u32, 0), rooms.physical_profiles.count());
            failures += 1;
            continue;
        };
        defer candidate.deinit();
        fail.fail_index = std.math.maxInt(usize);
        var wrong = testProfile();
        wrong.fec.redundancy += 1;
        try std.testing.expectError(error.InvalidProfile, domain.withLocked(Cut{ .domain = domain, .plan = candidate, .profile = wrong, .publish = false }, Cut.run));
        try std.testing.expectEqualDeep(old, mapState(rooms.profiles));
        var equal_tail = testProfile();
        for (equal_tail.codecs[equal_tail.codec_count..]) |*codec| codec.* = .{ .tag = .raw, .clock_rate = 9000, .params = 2 };
        try domain.withLocked(Cut{ .domain = domain, .plan = candidate, .profile = equal_tail, .publish = true }, Cut.run);
        try std.testing.expect(rooms.transportProfileOf("#public").?.eql(testProfile()));
        try std.testing.expectEqual(@as(u32, 0), rooms.physical_profiles.count());
        succeeded = true;
        break;
    }
    try std.testing.expect(succeeded and failures >= 4);
}

test "prepared Room departure observations retain exact sibling and last-display transitions" {
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("Room transition Domain rows");
    var call: ?routing.CallId = null;
    defer cleanupRoomDomainTest(domain, call);
    var rooms = MediaRooms.init(testing.allocator);
    defer rooms.deinit();
    const a = routing.ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const b = routing.ClientId{ .shard = 0, .slot = 1, .gen = 0 };
    call = try publishRoomJoinTest(domain, &rooms, a, .voice);
    _ = try publishRoomJoinTest(domain, &rooms, b, .video);
    const Cut = struct {
        domain: *routing.Domain,
        departure: *routing.PreparedClientDeparture,
        rooms: *PreparedRoomClientDeparture,
        fn run(scope: *routing.Locked, ctx: @This()) !void {
            try ctx.departure.validateLocked(ctx.domain, scope);
            try ctx.rooms.validateLocked(ctx.domain, scope, ctx.departure);
            ctx.rooms.commitLocked(ctx.domain, scope);
            ctx.departure.commitLocked(ctx.domain, scope);
        }
    };
    for ([_]routing.ClientId{ a, b }, 0..) |id, n| {
        const departure = try domain.prepareClientDeparture(id);
        defer departure.deinit();
        const candidate = try rooms.prepareClientDeparture(departure);
        defer candidate.deinit();
        try testing.expectEqual(@as(usize, 1), candidate.count());
        try testing.expectError(error.InvalidRequest, candidate.transition(1));
        try testing.expectError(error.InvalidRequest, candidate.transition(std.math.maxInt(usize)));
        const observed = try candidate.transition(0);
        try testing.expectEqualStrings("#departure", observed.channel);
        try testing.expectEqualStrings("same", observed.display);
        try testing.expect(observed.had_member);
        try testing.expectEqual(n == 0, observed.display_remains);
        try testing.expectEqual(n == 1, observed.drops_room);
        try domain.withLocked(Cut{ .domain = domain, .departure = departure, .rooms = candidate }, Cut.run);
        // Preparation metadata remains retained after pure publication, so
        // the caller can dispose its copied event custody after the cut.
        const retained = try candidate.transition(0);
        try testing.expectEqualStrings(observed.channel, retained.channel);
        try testing.expectEqualStrings(observed.display, retained.display);
        try testing.expectEqual(observed.had_member, retained.had_member);
        try testing.expectEqual(observed.display_remains, retained.display_remains);
        try testing.expectEqual(observed.drops_room, retained.drops_room);
    }
    try testing.expectEqual(@as(u32, 0), rooms.physical_members.count());
    try testing.expectEqual(@as(u32, 0), rooms.rooms.count());
}

test "prepared Room departure observations never invent a member for offer-only transport" {
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("offer-only Room transition Domain rows");
    var rooms = MediaRooms.init(testing.allocator);
    defer rooms.deinit();
    const id = routing.ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const offers = try domain.prepareOffers("#offer-only", id, &.{.{ .leg = .native, .mode = .legacy_group }});
    defer offers.deinit();
    const Publish = struct {
        domain: *routing.Domain,
        offers: *routing.PreparedOffers,
        fn run(scope: *routing.Locked, ctx: @This()) routing.Error!void {
            try ctx.offers.validateLocked(ctx.domain, scope);
            ctx.offers.commitLocked(ctx.domain, scope);
        }
    };
    try domain.withLocked(Publish{ .domain = domain, .offers = offers }, Publish.run);
    const offer_call = offers.preview().call;
    const Cleanup = struct {
        domain: *routing.Domain,
        call: routing.CallId,
        id: routing.ClientId,
        fn run(scope: *routing.Locked, ctx: @This()) routing.Error!void {
            try ctx.domain.revokeOffersLocked(scope, ctx.call, ctx.id);
        }
    };
    defer domain.withLocked(Cleanup{ .domain = domain, .call = offer_call, .id = id }, Cleanup.run) catch @panic("offer-only transition cleanup");
    const departure = try domain.prepareClientDeparture(id);
    defer departure.deinit();
    const candidate = try rooms.prepareClientDeparture(departure);
    defer candidate.deinit();
    try testing.expectEqual(@as(usize, 1), candidate.count());
    const observed = try candidate.transition(0);
    try testing.expectEqualStrings("#offer-only", observed.channel);
    try testing.expectEqualStrings("", observed.display);
    try testing.expect(!observed.had_member and !observed.display_remains and !observed.drops_room);
    const Retire = struct {
        domain: *routing.Domain,
        departure: *routing.PreparedClientDeparture,
        candidate: *PreparedRoomClientDeparture,
        fn run(scope: *routing.Locked, ctx: @This()) !void {
            try ctx.departure.validateLocked(ctx.domain, scope);
            try ctx.candidate.validateLocked(ctx.domain, scope, ctx.departure);
            ctx.candidate.commitLocked(ctx.domain, scope);
            ctx.departure.commitLocked(ctx.domain, scope);
        }
    };
    try domain.withLocked(Retire{ .domain = domain, .departure = departure, .candidate = candidate }, Retire.run);
}

const ExternalRoomOwnersTest = struct {
    rows: []const MediaRooms.ExternalDepartureOwner,
    index: usize = 0,
    fn next(self: *@This()) PreparedError!?MediaRooms.ExternalDepartureOwner {
        if (self.index == self.rows.len) return null;
        const row = self.rows[self.index];
        self.index += 1;
        return row;
    }
};

test "prepared Room external owners preserve same and disjoint legacy kinds flags and shared metadata" {
    for ([_]MediaKind{ .voice, .video }) |legacy_kind| {
        const domain = try routing.Domain.create(testing.allocator);
        defer domain.destroyQuiesced() catch @panic("external Room source remained");
        var call: ?routing.CallId = null;
        defer cleanupRoomDomainTest(domain, call);
        var rooms = MediaRooms.init(testing.allocator);
        defer rooms.deinit();
        const graph = routing.ClientId{ .shard = 0, .slot = 0, .gen = 0 };
        const flat = routing.ClientId{ .shard = 0, .slot = 1, .gen = 0 };
        call = try publishRoomJoinTest(domain, &rooms, graph, .voice);
        try rooms.join("#departure", "same", legacy_kind);
        if (legacy_kind == .voice) {
            try testing.expect(rooms.setMuted("#departure", "same", legacy_kind, true));
        } else try testing.expect(rooms.setSpeaking("#departure", "same", legacy_kind, true));
        const profile = testProfile();
        try rooms.setProfile("#departure", profile.slice(), profile.fec);
        try rooms.setBreakout("#departure", "same", "legacy-survivor");
        try rooms.setHand("#departure", "same", true);
        const rows = [_]MediaRooms.ExternalDepartureOwner{
            .{ .channel = "#departure", .participant = try media.ParticipantId.init("same"), .client = graph, .kind_bits = 1 << @backingInt(MediaKind.voice) },
            .{ .channel = "#departure", .participant = try media.ParticipantId.init("same"), .client = flat, .kind_bits = @as(u8, 1) << @backingInt(legacy_kind) },
        };
        const departure = try domain.prepareDeparture(call.?, graph);
        defer departure.deinit();
        const plan = try rooms.prepareDepartureWithExternalOwners(departure, "#departure", ExternalRoomOwnersTest{ .rows = &rows });
        defer plan.deinit();
        try testing.expect(plan.transition().display_remains and !plan.transition().drops_room);
        try domain.withLocked(RoomDepartureTestCut{ .domain = domain, .departure = departure, .room = plan }, RoomDepartureTestCut.run);
        try testing.expectEqual(@as(u32, 0), rooms.physical_members.count());
        const survivor = rooms.room("#departure").?.participant(try media.ParticipantId.init("same")).?;
        try testing.expectEqual(@as(u8, 1) << @backingInt(legacy_kind), survivor.joined.bits);
        try testing.expectEqual(legacy_kind == .voice, survivor.muted.contains(legacy_kind));
        try testing.expectEqual(legacy_kind == .video, survivor.speaking.contains(legacy_kind));
        try testing.expect(profile.eql(rooms.profileOf("#departure").?));
        try testing.expectEqualStrings("legacy-survivor", rooms.breakoutOf("#departure", "same"));
        try testing.expect(rooms.handRaised("#departure", "same"));
        // The display survivor is NOT a replacement protected member. The
        // old CallId no longer owns this full physical client or packet scope.
        try testing.expect(!(try domain.hasCurrentMembership("#departure", flat)));
    }
}

fn externalRoomDepartureOom(allocator: std.mem.Allocator) !void {
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("external Room OOM source remained");
    var call: ?routing.CallId = null;
    defer cleanupRoomDomainTest(domain, call);
    var rooms = MediaRooms.init(allocator);
    defer rooms.deinit();
    const graph = routing.ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const flat = routing.ClientId{ .shard = 0, .slot = 1, .gen = 0 };
    call = try publishRoomJoinTest(domain, &rooms, graph, .voice);
    try rooms.join("#departure", "same", .video);
    try rooms.setHand("#departure", "same", true);
    const original_room = rooms.room("#departure").?;
    const snapshot = try original_room.capture();
    const revision = rooms.transport_revision;
    const members = mapState(rooms.physical_members);
    const rows = [_]MediaRooms.ExternalDepartureOwner{.{ .channel = "#departure", .participant = try media.ParticipantId.init("same"), .client = flat, .kind_bits = 1 << @backingInt(MediaKind.video) }};
    const departure = try domain.prepareDeparture(call.?, graph);
    defer departure.deinit();
    const attempt = rooms.prepareDepartureWithExternalOwners(departure, "#departure", ExternalRoomOwnersTest{ .rows = &rows });
    if (attempt) |plan| {
        plan.deinit(); // reversible candidate, never published
    } else |err| {
        try testing.expect(original_room == rooms.room("#departure").?);
        try testing.expectEqualDeep(snapshot, try original_room.capture());
        try testing.expectEqualDeep(members, mapState(rooms.physical_members));
        try testing.expectEqual(revision, rooms.transport_revision);
        try testing.expect(rooms.handRaised("#departure", "same"));
        return err;
    }
    try testing.expect(original_room == rooms.room("#departure").?);
    try testing.expectEqualDeep(snapshot, try original_room.capture());
    try testing.expectEqual(revision, rooms.transport_revision);
}

test "prepared Room external-owner allocation failures leave original graph display and metadata unchanged" {
    try testing.checkAllAllocationFailures(testing.allocator, externalRoomDepartureOom, .{});
}

test "prepared Room external-owner census rejects foreign channel display and unbacked kinds before mutation" {
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("external census source remained");
    var call: ?routing.CallId = null;
    defer cleanupRoomDomainTest(domain, call);
    var rooms = MediaRooms.init(testing.allocator);
    defer rooms.deinit();
    const graph = routing.ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const flat = routing.ClientId{ .shard = 0, .slot = 1, .gen = 0 };
    call = try publishRoomJoinTest(domain, &rooms, graph, .voice);
    const original = try rooms.room("#departure").?.capture();
    const departure = try domain.prepareDeparture(call.?, graph);
    defer departure.deinit();
    var rows = [_]MediaRooms.ExternalDepartureOwner{.{ .channel = "#foreign", .participant = try media.ParticipantId.init("same"), .client = flat, .kind_bits = 1 }};
    try testing.expectError(error.InvalidRequest, rooms.prepareDepartureWithExternalOwners(departure, "#departure", ExternalRoomOwnersTest{ .rows = &rows }));
    rows[0].channel = "#departure";
    rows[0].participant = try media.ParticipantId.init("other");
    try testing.expectError(error.InvalidRequest, rooms.prepareDepartureWithExternalOwners(departure, "#departure", ExternalRoomOwnersTest{ .rows = &rows }));
    rows[0].participant = try media.ParticipantId.init("same");
    rows[0].kind_bits = 8;
    try testing.expectError(error.InvalidRequest, rooms.prepareDepartureWithExternalOwners(departure, "#departure", ExternalRoomOwnersTest{ .rows = &rows }));
    rows[0].kind_bits = 2; // no such joined legacy video bit exists
    try testing.expectError(error.InvalidSnapshot, rooms.prepareDepartureWithExternalOwners(departure, "#departure", ExternalRoomOwnersTest{ .rows = &rows }));
    try testing.expectEqualDeep(original, try rooms.room("#departure").?.capture());
    try testing.expect(try domain.hasCurrentMembership("#departure", graph));
    try testing.expect(!(try domain.hasCurrentMembership("#departure", flat)));
}

fn setCaseMemberMetadata(rooms: *MediaRooms, channel: []const u8, participant: []const u8) !void {
    const profile = testProfile();
    try rooms.setBreakout(channel, participant, "stage");
    try rooms.setPosition(channel, participant, .{ .x = 7, .y = -4 });
    try rooms.setHand(channel, participant, true);
    try rooms.setParticipantProfile(channel, participant, profile.slice(), profile.fec);
    try testing.expect(try rooms.setConsent(channel, participant, true));
    try testing.expect(try rooms.setQuality(channel, participant, .{ .loss_pct = 3, .rtt_ms = 41, .spatial = 1, .bitrate_kbps = 256 }));
}

fn expectCaseMemberMetadata(rooms: *const MediaRooms, channel: []const u8, participant: []const u8, present: bool) !void {
    return expectCaseMemberMetadataWithBreakout(rooms, channel, participant, present, if (present) "stage" else default_breakout);
}

fn expectCaseMemberMetadataWithBreakout(rooms: *const MediaRooms, channel: []const u8, participant: []const u8, present: bool, expected_breakout: []const u8) !void {
    try testing.expectEqualStrings(expected_breakout, rooms.breakoutOf(channel, participant));
    try testing.expectEqual(if (present) Position{ .x = 7, .y = -4 } else Position{}, rooms.positionOf(channel, participant));
    try testing.expectEqual(present, rooms.handRaised(channel, participant));
    try testing.expectEqual(present, rooms.hasConsent(channel, participant));
    try testing.expectEqual(present, rooms.participantProfileOf(channel, participant) != null);
    try testing.expectEqual(present, rooms.qualityOf(channel, participant) != null);
    if (present) {
        try testing.expect(rooms.participantProfileOf(channel, participant).?.eql(testProfile()));
        try testing.expectEqual(@as(u8, 3), rooms.qualityOf(channel, participant).?.loss_pct);
    }
}

fn fillCaseMetadataFixture(rooms: *MediaRooms) !void {
    const profile = testProfile();
    for ([_][]const u8{ "#ALPHA", "#BETA" }) |channel| {
        try rooms.join(channel, "Alice", .voice);
        try rooms.setProfile(channel, profile.slice(), profile.fec);
        try setCaseMemberMetadata(rooms, channel, "Alice");
        try testing.expect(try rooms.startRecording(channel, "Alice"));
    }
}

fn expectRawCaseSnapshot(rooms: *MediaRooms, snapshot: *const Snapshot) !void {
    for (snapshot.rooms) |row| {
        const entry = rooms.rooms.getEntry(row.key) orelse return error.TestUnexpectedResult;
        try testing.expectEqualStrings(row.key, entry.key_ptr.*);
        try testing.expectEqualDeep(row.room, try entry.value_ptr.*.capture());
    }
    inline for (.{ "breakouts", "positions", "hands", "profiles", "participant_profiles", "consents", "recordings", "qualities" }) |field| {
        for (@field(snapshot, field)) |row| {
            const entry = @field(rooms, field).getEntry(row.key) orelse return error.TestUnexpectedResult;
            try testing.expectEqualStrings(row.key, entry.key_ptr.*);
            if (@TypeOf(row.value) != void) try testing.expectEqualDeep(row.value, entry.value_ptr.*);
        }
    }
    for (snapshot.queues) |row| {
        const entry = rooms.queues.getEntry(row.key) orelse return error.TestUnexpectedResult;
        try testing.expectEqualStrings(row.key, entry.key_ptr.*);
        try testing.expectEqual(row.items.len, entry.value_ptr.items.len);
        for (row.items, entry.value_ptr.items) |expected, actual| try testing.expectEqualStrings(expected, actual);
    }
}

test "media room ASCII metadata preserves exact participants and retires legacy attachments in either order" {
    for ([_]bool{ false, true }) |reverse| {
        var rooms = MediaRooms.init(testing.allocator);
        defer rooms.deinit();
        const profile = testProfile();
        try fillCaseMetadataFixture(&rooms);
        try rooms.join("#aLpHa", "alice", .video);
        try setCaseMemberMetadata(&rooms, "#AlPhA", "alice");
        try expectCaseMemberMetadata(&rooms, "#alpha", "Alice", true);
        try expectCaseMemberMetadata(&rooms, "#ALPHA", "alice", true);
        try expectCaseMemberMetadata(&rooms, "#alpha", "ALICE", false);
        try testing.expect(rooms.profileOf("#alpha").?.eql(profile));
        try testing.expect(rooms.recordingOf("#alpha").?.active);
        var queue: [3][]const u8 = undefined;
        try testing.expectEqual(@as(usize, 2), rooms.copySpeakQueue("#alpha", &queue));
        try testing.expectEqualStrings("Alice", queue[0]);
        try testing.expectEqualStrings("alice", queue[1]);
        // Revoking consent through another spelling cannot hide from the
        // recording authorization/read/stop paths or a later unanimous check.
        try testing.expect(try rooms.setConsent("#aLPha", "Alice", false));
        try testing.expect(!rooms.hasConsent("#ALPHA", "Alice"));
        try testing.expect(!rooms.allConsented("#alpha"));
        try testing.expect(rooms.stopRecording("#alPHA"));
        try testing.expect(!rooms.recordingOf("#ALPHA").?.active);
        try testing.expect(!try rooms.startRecording("#alpha", "alice"));
        try testing.expect(try rooms.setConsent("#alpha", "Alice", true));
        try testing.expect(try rooms.startRecording("#aLpHa", "Alice"));
        const first = if (reverse) "alice" else "Alice";
        const survivor = if (reverse) "Alice" else "alice";
        try testing.expect(rooms.leaveAll("#AlPhA", first));
        try expectCaseMemberMetadata(&rooms, "#ALPHA", first, false);
        try expectCaseMemberMetadata(&rooms, "#alpha", survivor, true);
        try testing.expectEqual(@as(usize, 1), rooms.copySpeakQueue("#aLPHA", &queue));
        try testing.expectEqualStrings(survivor, queue[0]);
        try testing.expect(rooms.recordingOf("#alpha").?.active);
        try testing.expect(rooms.leaveAll("#aLPHA", survivor));
        try testing.expect(rooms.room("#ALPHA") == null);
        try testing.expect(rooms.profileOf("#alpha") == null);
        try testing.expect(rooms.recordingOf("#alpha") == null);
        try testing.expectEqual(@as(usize, 0), rooms.copySpeakQueue("#alpha", &queue));
        try expectCaseMemberMetadata(&rooms, "#alpha", survivor, false);
        try expectCaseMemberMetadata(&rooms, "#beta", "Alice", true);
        try testing.expect(rooms.profileOf("#beta").?.eql(profile));
        try testing.expect(rooms.recordingOf("#beta").?.active);
    }
}

test "media room ASCII metadata mutations retain stored spelling and clear all equivalent participant profiles" {
    var rooms = MediaRooms.init(testing.allocator);
    defer rooms.deinit();
    try fillCaseMetadataFixture(&rooms);
    try rooms.setBreakout("#alpha", "Alice", "changed");
    try testing.expectEqualStrings("changed", rooms.breakoutOf("#AlPhA", "Alice"));
    try testing.expectEqualStrings("#ALPHA\x00Alice", rooms.breakouts.getEntry("#alpha\x00Alice").?.key_ptr.*);
    try rooms.setBreakout("#alpha", "Alice", "stage");
    try rooms.setPosition("#aLPHA", "Alice", .{ .x = 8, .y = 9 });
    try testing.expectEqual(Position{ .x = 8, .y = 9 }, rooms.positionOf("#ALPHA", "Alice"));
    rooms.clearPosition("#alPHA", "Alice");
    try testing.expectEqual(Position{}, rooms.positionOf("#ALPHA", "Alice"));
    try rooms.setHand("#alpha", "Alice", false);
    try testing.expect(!rooms.handRaised("#ALPHA", "Alice"));
    var queue: [2][]const u8 = undefined;
    try testing.expectEqual(@as(usize, 0), rooms.copySpeakQueue("#ALPHA", &queue));
    const profile = testProfile();
    try rooms.setParticipantProfile("#ALPHA", "alice", profile.slice(), profile.fec);
    for (0..max_participants + 1) |n| {
        var name: [32]u8 = undefined;
        try rooms.setParticipantProfile("#aLPhA", try std.fmt.bufPrint(&name, "prejoin-{d}", .{n}), profile.slice(), profile.fec);
    }
    try rooms.setProfile("#aLpHa", profile.slice(), profile.fec);
    try testing.expectEqual(@as(u32, 1), rooms.participant_profiles.count());
    try testing.expect(rooms.participantProfileOf("#alpha", "Alice") == null);
    try testing.expect(rooms.participantProfileOf("#alpha", "alice") == null);
    try testing.expectEqualStrings("#ALPHA", rooms.profiles.getEntry("#alpha").?.key_ptr.*);
    try expectCaseMemberMetadata(&rooms, "#beta", "Alice", true);
    rooms.clearBreakout("#aLPhA", "Alice");
    rooms.clearConsent("#aLPhA", "Alice");
    rooms.clearQuality("#aLPhA", "Alice");
    rooms.clearRecording("#aLPhA");
    rooms.clearProfile("#aLPhA");
    try expectCaseMemberMetadata(&rooms, "#alpha", "Alice", false);
    try testing.expect(rooms.recordingOf("#alpha") == null);
    try testing.expect(rooms.profileOf("#alpha") == null);
}

test "media room ASCII metadata strict snapshot aliases reject every map before allocation" {
    var rooms = MediaRooms.init(testing.allocator);
    defer rooms.deinit();
    try fillCaseMetadataFixture(&rooms);
    inline for (.{ "rooms", "breakouts", "positions", "hands", "profiles", "participant_profiles", "consents", "recordings", "qualities", "queues" }) |field| {
        var snapshot = try rooms.capture();
        defer snapshot.deinit();
        const rows = @field(snapshot, field);
        try testing.expectEqual(@as(usize, 2), rows.len);
        const alias = try testing.allocator.dupe(u8, rows[0].key);
        for (alias) |*byte| {
            if (byte.* == 0) break;
            byte.* = std.ascii.toLower(byte.*);
        }
        testing.allocator.free(rows[1].key);
        rows[1].key = alias;
        try testing.expectError(error.InvalidSnapshot, snapshot.validate());
        var fail = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
        try testing.expectError(error.InvalidSnapshot, MediaRooms.prepareRestore(fail.allocator(), &snapshot, &.{}));
        try testing.expect(!fail.has_induced_failure);
        try expectCaseMemberMetadata(&rooms, "#alpha", "Alice", true);
        try expectCaseMemberMetadata(&rooms, "#beta", "Alice", true);
    }
}

test "media room ASCII metadata snapshot preserves raw uppercase rows and cross-case queue hand references" {
    var rooms = MediaRooms.init(testing.allocator);
    defer rooms.deinit();
    try fillCaseMetadataFixture(&rooms);
    var snapshot = try rooms.capture();
    defer snapshot.deinit();
    // Deliberately distinct spellings in structured rows remain one channel;
    // the hand participant suffix must still be exact.
    for (snapshot.queues) |row| for (row.key) |*byte| {
        byte.* = std.ascii.toLower(byte.*);
    };
    try snapshot.validate();
    var restored = try MediaRooms.prepareRestore(testing.allocator, &snapshot, &.{});
    defer restored.deinit();
    try expectRawCaseSnapshot(&restored, &snapshot);
    try expectCaseMemberMetadata(&restored, "#alpha", "Alice", true);
    try expectCaseMemberMetadata(&restored, "#beta", "Alice", true);
    try testing.expect(restored.recordingOf("#alpha").?.active);
    const recording = restored.recordingOf("#alpha").?;
    try testing.expectEqualStrings("Alice", recording.by());
    snapshot.hands[0].key[snapshot.hands[0].key.len - 1] = 'X';
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
}

test "media room ASCII metadata never folds UTF8 or participant suffix and refuses malformed composite names" {
    var rooms = MediaRooms.init(testing.allocator);
    defer rooms.deinit();
    for ([_][]const u8{ "#é", "#É" }) |channel| {
        try rooms.join(channel, "Alice", .voice);
        try rooms.join(channel, "alice", .voice);
        try setCaseMemberMetadata(&rooms, channel, "Alice");
        try setCaseMemberMetadata(&rooms, channel, "alice");
    }
    try rooms.setBreakout("#é", "Alice", "lower");
    try rooms.setBreakout("#É", "Alice", "upper");
    try testing.expectEqualStrings("lower", rooms.breakoutOf("#é", "Alice"));
    try testing.expectEqualStrings("upper", rooms.breakoutOf("#É", "Alice"));
    try testing.expectEqualStrings("stage", rooms.breakoutOf("#é", "alice"));
    try testing.expect(!ParticipantKeyContext.eql(.{}, "#x\x00Alice", "#X\x00alice"));
    try testing.expect(!ParticipantKeyContext.eql(.{}, "#x\x00a", "#xa\x00"));
    try testing.expect(!ParticipantKeyContext.eql(.{}, "#é\x00Alice", "#É\x00Alice"));
    try testing.expect(!ParticipantKeyContext.eql(.{}, "#x\x00é", "#X\x00É"));
    try testing.expect(!ChannelKeyContext.eql(.{}, "#[x]", "#{x}"));
    var buf: [256]u8 = undefined;
    try testing.expect(MediaRooms.breakoutKey(&buf, "#bad\x00extra", "Alice") == null);
    try testing.expect(MediaRooms.breakoutKey(&buf, "#ok", "Al\x00ice") == null);
    try testing.expect(!validCompositeKey("#ok\x00Al\x00ice"));
    var snapshot = try rooms.capture();
    defer snapshot.deinit();
    try snapshot.validate();
    var restored = try MediaRooms.prepareRestore(testing.allocator, &snapshot, &.{});
    defer restored.deinit();
    try expectRawCaseSnapshot(&restored, &snapshot);
    try testing.expect(restored.leaveAll("#é", "Alice"));
    try expectCaseMemberMetadataWithBreakout(&restored, "#É", "Alice", true, "upper");
    try expectCaseMemberMetadata(&restored, "#é", "alice", true);
}

fn restoreCaseMetadataOom(allocator: std.mem.Allocator) !void {
    var rooms = MediaRooms.init(testing.allocator);
    defer rooms.deinit();
    try fillCaseMetadataFixture(&rooms);
    var snapshot = try rooms.capture();
    defer snapshot.deinit();
    const old_rooms = mapState(rooms.rooms);
    const old_profiles = mapState(rooms.profiles);
    const old_breakouts = mapState(rooms.breakouts);
    var restored = MediaRooms.prepareRestore(allocator, &snapshot, &.{}) catch |err| {
        try testing.expectEqualDeep(old_rooms, mapState(rooms.rooms));
        try testing.expectEqualDeep(old_profiles, mapState(rooms.profiles));
        try testing.expectEqualDeep(old_breakouts, mapState(rooms.breakouts));
        try expectCaseMemberMetadata(&rooms, "#alpha", "Alice", true);
        try expectCaseMemberMetadata(&rooms, "#beta", "Alice", true);
        try snapshot.validate();
        return err;
    };
    defer restored.deinit();
    try expectRawCaseSnapshot(&restored, &snapshot);
    try expectCaseMemberMetadata(&restored, "#alpha", "Alice", true);
    try expectCaseMemberMetadata(&restored, "#beta", "Alice", true);
}

test "media room ASCII metadata full fresh restore allocation failures preserve every source row" {
    try testing.checkAllAllocationFailures(testing.allocator, restoreCaseMetadataOom, .{});
}

fn casePreparedDepartureBothOrders(reverse: bool) !void {
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("case metadata Domain rows");
    var call: ?routing.CallId = null;
    defer cleanupRoomDomainTest(domain, call);
    var rooms = MediaRooms.init(testing.allocator);
    defer rooms.deinit();
    const a = routing.ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const b = routing.ClientId{ .shard = 0, .slot = 1, .gen = 0 };
    // A unique legacy raw uppercase room is retained when prepared membership
    // adopts that geometry; the map must not insert a lower-case alias.
    try rooms.join("#DEPARTURE", "same", .voice);
    call = try publishRoomJoinTest(domain, &rooms, a, .voice);
    _ = try publishRoomJoinTest(domain, &rooms, b, .video);
    try testing.expectEqualStrings("#DEPARTURE", rooms.rooms.getEntry("#departure").?.key_ptr.*);
    const profile = testProfile();
    try rooms.setProfile("#DEPARTURE", profile.slice(), profile.fec);
    try setCaseMemberMetadata(&rooms, "#DEPARTURE", "same");
    try testing.expect(try rooms.startRecording("#dEpArTuRe", "same"));
    try rooms.join("#OTHER", "same", .voice);
    try rooms.setProfile("#OTHER", profile.slice(), profile.fec);
    try setCaseMemberMetadata(&rooms, "#OTHER", "same");
    try testing.expect(try rooms.startRecording("#OTHER", "same"));
    const ids = if (reverse) [_]routing.ClientId{ b, a } else [_]routing.ClientId{ a, b };
    for (ids, 0..) |id, n| {
        const departure = try domain.prepareDeparture(call.?, id);
        defer departure.deinit();
        const candidate = try rooms.prepareDeparture(departure, "#DePaRtUrE");
        defer candidate.deinit();
        try domain.withLocked(RoomDepartureTestCut{ .domain = domain, .departure = departure, .room = candidate }, RoomDepartureTestCut.run);
        try expectCaseMemberMetadata(&rooms, "#departure", "same", n == 0);
        try expectCaseMemberMetadata(&rooms, "#other", "same", true);
        try testing.expect(rooms.recordingOf("#other").?.active);
        try testing.expect(rooms.profileOf("#other").?.eql(profile));
    }
    try testing.expect(rooms.room("#DEPARTURE") == null);
    try testing.expect(rooms.recordingOf("#DEPARTURE") == null);
    try testing.expect(rooms.profileOf("#DEPARTURE") == null);
    var queue: [2][]const u8 = undefined;
    try testing.expectEqual(@as(usize, 0), rooms.copySpeakQueue("#DEPARTURE", &queue));
    try testing.expectEqual(@as(usize, 1), rooms.copySpeakQueue("#OTHER", &queue));
    try testing.expectEqualStrings("same", queue[0]);
}

test "media room ASCII metadata prepared departure preserves either sibling and unrelated channel" {
    try casePreparedDepartureBothOrders(false);
    try casePreparedDepartureBothOrders(true);
}

fn expectRawOldCaseKeys(rooms: *MediaRooms, comptime field: []const u8, count: usize) !void {
    for (0..count) |n| {
        var lower_buf: [32]u8 = undefined;
        var upper_buf: [32]u8 = undefined;
        const lower = try std.fmt.bufPrint(&lower_buf, "#old-{d}", .{n});
        const upper = try std.fmt.bufPrint(&upper_buf, "#OLD-{d}", .{n});
        const actual = @field(rooms, field).getEntry(lower) orelse return error.TestUnexpectedResult;
        try testing.expectEqualStrings(upper, actual.key_ptr.*);
    }
}

fn casePreparedRoomGrowthOom(allocator: std.mem.Allocator) !void {
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("case room growth Domain rows");
    var rooms = MediaRooms.init(allocator);
    defer rooms.deinit();
    var count: usize = 0;
    while (count == 0 or rooms.rooms.unmanaged.available != 0) : (count += 1) {
        var name: [32]u8 = undefined;
        try rooms.join(try std.fmt.bufPrint(&name, "#OLD-{d}", .{count}), "Alice", .voice);
    }
    const table = mapState(rooms.rooms);
    const first_key = rooms.rooms.getEntry("#old-0").?.key_ptr.*;
    const id = routing.ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const membership = try domain.prepareMembership("#NEW", id, 1);
    defer membership.deinit();
    const candidate = rooms.prepareJoin(membership.preview(), "#nEw", "Alice", .voice) catch |err| {
        try testing.expectEqualDeep(table, mapState(rooms.rooms));
        try testing.expect(rooms.rooms.getEntry("#OLD-0").?.key_ptr.*.ptr == first_key.ptr);
        try expectRawOldCaseKeys(&rooms, "rooms", count);
        return err;
    };
    defer candidate.deinit();
    try testing.expect(joinPlan(candidate).growth != null);
    try testing.expectEqualDeep(table, mapState(rooms.rooms));
    var committed = false;
    defer if (committed) domain.withLocked(RevokeRoutingTest{ .domain = domain, .call = membership.preview().call, .client = id }, RevokeRoutingTest.run) catch @panic("case room growth cleanup");
    try domain.withLocked(JoinedRoomTest{ .domain = domain, .membership = membership, .room = candidate }, JoinedRoomTest.run);
    committed = true;
    try testing.expect(rooms.isParticipant("#NEW", "Alice"));
    try testing.expect(rooms.rooms.getEntry("#OLD-0").?.key_ptr.*.ptr == first_key.ptr);
    try expectRawOldCaseKeys(&rooms, "rooms", count);
}

fn casePreparedProfileGrowthOom(allocator: std.mem.Allocator) !void {
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("case profile growth Domain rows");
    var rooms = MediaRooms.init(allocator);
    defer rooms.deinit();
    const profile = testProfile();
    var count: usize = 0;
    while (count == 0 or rooms.profiles.unmanaged.available != 0) : (count += 1) {
        var name: [32]u8 = undefined;
        try rooms.setProfile(try std.fmt.bufPrint(&name, "#OLD-{d}", .{count}), profile.slice(), profile.fec);
    }
    const table = mapState(rooms.profiles);
    const first_key = rooms.profiles.getEntry("#old-0").?.key_ptr.*;
    const candidate = rooms.prepareSharedProfile("#nEw", profile) catch |err| {
        try testing.expectEqualDeep(table, mapState(rooms.profiles));
        try testing.expect(rooms.profiles.getEntry("#OLD-0").?.key_ptr.*.ptr == first_key.ptr);
        try expectRawOldCaseKeys(&rooms, "profiles", count);
        return err;
    };
    defer candidate.deinit();
    try testing.expect(sharedProfilePlan(candidate).growth != null);
    try testing.expectEqualDeep(table, mapState(rooms.profiles));
    const Cut = struct {
        domain: *routing.Domain,
        plan: *PreparedSharedProfile,
        profile: CallProfile,
        fn run(scope: *routing.Locked, ctx: @This()) PreparedError!void {
            try ctx.plan.validateLocked(ctx.domain, scope, ctx.profile);
            ctx.plan.commitLocked(ctx.domain, scope);
        }
    };
    try domain.withLocked(Cut{ .domain = domain, .plan = candidate, .profile = profile }, Cut.run);
    try testing.expect(rooms.transportProfileOf("#NEW").?.eql(profile));
    try testing.expect(rooms.profiles.getEntry("#OLD-0").?.key_ptr.*.ptr == first_key.ptr);
    try expectRawOldCaseKeys(&rooms, "profiles", count);
}

test "media room ASCII metadata prepared growth allocation failures preserve old raw keys and retry" {
    try testing.checkAllAllocationFailures(testing.allocator, casePreparedRoomGrowthOom, .{});
    try testing.checkAllAllocationFailures(testing.allocator, casePreparedProfileGrowthOom, .{});
}
