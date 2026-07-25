// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Length-prefixed S2S wire frames for Undertow mesh links.
//!
//! The frame header is exactly five bytes:
//!   * u8 frame type tag
//!   * u32 little-endian payload length
//! followed by `length` payload bytes.
const std = @import("std");

pub const header_len: usize = 5;
pub const length_len: usize = 4;
/// Default upper bound on one complete S2S frame (header + payload). Session
/// migration / portable-snapshot ceilings are derived from this value, so it
/// stays 1 MiB. Secured media cascade raises the *per-peer* `max_frame_size`
/// (see `media_ws_relay.required_max_frame_size`) without widening the
/// snapshot wire budget.
pub const default_max_frame_size: usize = 1024 * 1024;

const endian = .little;

pub const EncodeError = error{
    BufferTooSmall,
    PayloadTooLarge,
};

pub const DecodeError = std.mem.Allocator.Error || error{
    MalformedFrame,
    OversizeFrame,
    Truncated,
};

pub const FrameType = enum(u8) {
    HANDSHAKE = 0x01,
    BURST = 0x02,
    DELTA = 0x03,
    GOSSIP = 0x04,
    PING = 0x05,
    PONG = 0x06,
    QUIT = 0x07,
    MEMBERSHIP = 0x08,
    MESSAGE = 0x09,
    /// Signed cross-mesh operator authorization grant (oper_cred_share bytes),
    /// verified against the sending peer's identity on receipt.
    OPER_GRANT = 0x0A,
    CHANNEL_MODE_FLAGS = 0x0B,
    /// Channel list-mode fact (+b/+e/+I), LWW by payload HLC.
    CHANNEL_LIST = 0x0C,
    /// IRCX channel PROP convergence event (channel/key/value/owner LWW by hlc).
    CHANNEL_PROP = 0x0D,
    /// Channel topic-text fact (channel/topic/setter/set_at), LWW by payload HLC.
    TOPIC = 0x0E,
    /// Remote user nick change (old/new nick + identity) for live `NICK` lines.
    NICKCHANGE = 0x0F,
    /// Parameter/IRCX channel state snapshot (+k/+l/+j/+f/private/hidden/ext).
    CHANNEL_MODE_STATE = 0x10,
    /// Live session-migration capsule (migration_relay frame bytes): a signed
    /// snapshot the origin ships to the owning node so a reconnecting client
    /// lands with its nick/umodes/account/away/channels restored.
    SESSION_MIGRATE = 0x11,
    /// IRCX user/member PROP convergence event (entity_kind/entity/key/value/owner
    /// LWW by hlc). The non-channel counterpart of CHANNEL_PROP: channels ride
    /// CHANNEL_PROP, `user`/`member` entities ride ENTITY_PROP.
    ENTITY_PROP = 0x12,
    /// Network-wide clone counts: a batch of (salted-IP-hash, count) pairs this
    /// node currently holds. Raw IPs never appear — only keyed hashes. Decoded by
    /// the `mesh_clones` binary codec and attributed to the authenticated link.
    CLONE_COUNT = 0x13,
    /// Network-wide operator event: a one-shot Event-Spine alert (raid, spamtrap,
    /// oper action, …) raised on `origin_server`, fanned to every node so opers
    /// anywhere see it, rendered with the origin server name. Carries
    /// {origin_server, category, severity, message}; signed like other facts.
    OPER_EVENT = 0x14,
    /// Network-wide operator OBSERVE feed: a one-shot lifecycle record (connect,
    /// quit, nick, oper-up) for a watched subject raised on `origin_server`, fanned
    /// to every node so a standing `EVENT OBSERVE <mask>` matches network-wide.
    /// Carries {action, origin_server, nick, user, host, account, detail}; signed
    /// (the subject's host is the REAL/uncloaked host — an operator-trust surface).
    OBSERVE_EVENT = 0x15,
    /// Targeted cross-mesh operator KILL: the owning node disconnects its local
    /// `target` on behalf of operator `killer` who issued it on `origin_server`.
    /// A one-shot COMMAND (not stored); the killer's node already enforced the
    /// `client_kill` privilege and signs the frame with its Mooring identity.
    /// Carries {origin_server, killer, target, reason}.
    KILL = 0x16,
    /// Network-wide `mesh`-scope WARD (network-ban) convergence: an add or remove
    /// of a Warden entry, fanned to every secured peer so an already-running node
    /// enforces (or forgets) the ban live. Carries a `warden` wire record
    /// {op, match, pattern, action, reason, set_by, created_ms, expires_ms};
    /// signed like other oper-trust facts (the setter is operator authority).
    WARD = 0x17,

    /// Full-state resync request. Sent by a node that has just resumed a mesh link
    /// across a Helix hot upgrade: the encrypted socket was preserved (the peer
    /// never saw a drop), but the resumed node's converged view of the peer's
    /// roster/props/topics was intentionally discarded. On receipt, the peer
    /// re-runs its full state burst (the same one a fresh link establishment
    /// sends), reconverging the resumed node without any visible netsplit. Empty
    /// payload; unsigned (a trivial control trigger carrying no trusted state).
    RESYNC = 0x18,
    /// Merkle/RBSR anti-entropy repair summary for the peer's channel CRDT.
    /// Capability-gated by the S2S handshake; older peers skip unknown tags.
    REPAIR_SUMMARY = 0x19,
    /// Request records whose hashes differ from a received repair summary.
    REPAIR_REQUEST = 0x1A,
    /// Repair records that backfill the requested CRDT entities.
    REPAIR_RESPONSE = 0x1B,
    /// Signed, secured-only Web Push hint for an offline memo/DM notification.
    /// Carries a bounded `memo_push_relay` record: {account, from, text preview}.
    /// The receiving node only runs its LOCAL Web Push worker/subscription store;
    /// no memo message or subscription state is replicated by this frame.
    /// MEMO_PUSH tag 0x1C.
    MEMO_PUSH = 0x1C,
    /// Signed consume tombstone for a portable session migration. Peers remove
    /// staged copies and retain a token tombstone so delayed offers cannot fork.
    SESSION_MIGRATE_CONSUMED = 0x1D,
    /// SESSION_REPLICA v2 signed upsert offer. Secured-link and capability gated;
    /// payload is a versioned `session_replica_frame` transport envelope.
    SESSION_REPLICA_OFFER = 0x1E,
    /// SESSION_REPLICA v2 signed receiver acknowledgment and route observation.
    SESSION_REPLICA_ACK = 0x1F,
    /// SESSION_REPLICA v2 signed removal tombstone (REVOKE).
    SESSION_REPLICA_REVOKE = 0x20,
    /// Secured-only multi-hop user relay with immutable origin-signed routing
    /// scope and non-bearer portable-session route identifiers.
    MESSAGE_V2 = 0x21,
    /// Short-lived positive proof that one SESSION_REPLICA origin still has a
    /// live exact-token attachment. Separately negotiated for rolling upgrades.
    SESSION_REPLICA_ATTACHMENT_LEASE = 0x22,
    /// Secured multi-hop Event Spine object. The inner OEVT v2 bytes retain the
    /// original author's signature and are forwarded without rewriting; the
    /// signed-frame envelope authenticates only the immediate transport peer.
    OPER_EVENT_V2 = 0x23,
    /// Hop receipt for a daemon-admitted immutable MESSAGE_V2 RelayId. A sender
    /// retains the exact wire until this secured, signed acknowledgment arrives.
    MESSAGE_V2_ACK = 0x24,
    /// Origin-only cascade of an already-validated browser Cadence binary
    /// WebSocket media datagram. Carries a bounded `media_ws_relay` record
    /// {channel, opaque datagram}. Receivers fan out locally to WS call
    /// participants and MUST NOT re-mesh (loop prevention is origin-only emit).
    /// Secured-signed; never re-verifies the browser MAC (origin already did).
    MEDIA_WS_DATAGRAM = 0x25,

    pub fn tag(self: FrameType) u8 {
        return @intFromEnum(self);
    }

    pub fn fromTag(tag_value: u8) ?FrameType {
        return switch (tag_value) {
            @intFromEnum(FrameType.HANDSHAKE) => .HANDSHAKE,
            @intFromEnum(FrameType.BURST) => .BURST,
            @intFromEnum(FrameType.DELTA) => .DELTA,
            @intFromEnum(FrameType.GOSSIP) => .GOSSIP,
            @intFromEnum(FrameType.PING) => .PING,
            @intFromEnum(FrameType.PONG) => .PONG,
            @intFromEnum(FrameType.QUIT) => .QUIT,
            @intFromEnum(FrameType.MEMBERSHIP) => .MEMBERSHIP,
            @intFromEnum(FrameType.MESSAGE) => .MESSAGE,
            @intFromEnum(FrameType.OPER_GRANT) => .OPER_GRANT,
            @intFromEnum(FrameType.CHANNEL_MODE_FLAGS) => .CHANNEL_MODE_FLAGS,
            @intFromEnum(FrameType.CHANNEL_LIST) => .CHANNEL_LIST,
            @intFromEnum(FrameType.CHANNEL_PROP) => .CHANNEL_PROP,
            @intFromEnum(FrameType.TOPIC) => .TOPIC,
            @intFromEnum(FrameType.NICKCHANGE) => .NICKCHANGE,
            @intFromEnum(FrameType.CHANNEL_MODE_STATE) => .CHANNEL_MODE_STATE,
            @intFromEnum(FrameType.SESSION_MIGRATE) => .SESSION_MIGRATE,
            @intFromEnum(FrameType.ENTITY_PROP) => .ENTITY_PROP,
            @intFromEnum(FrameType.CLONE_COUNT) => .CLONE_COUNT,
            @intFromEnum(FrameType.OPER_EVENT) => .OPER_EVENT,
            @intFromEnum(FrameType.OBSERVE_EVENT) => .OBSERVE_EVENT,
            @intFromEnum(FrameType.KILL) => .KILL,
            @intFromEnum(FrameType.WARD) => .WARD,
            @intFromEnum(FrameType.RESYNC) => .RESYNC,
            @intFromEnum(FrameType.REPAIR_SUMMARY) => .REPAIR_SUMMARY,
            @intFromEnum(FrameType.REPAIR_REQUEST) => .REPAIR_REQUEST,
            @intFromEnum(FrameType.REPAIR_RESPONSE) => .REPAIR_RESPONSE,
            @intFromEnum(FrameType.MEMO_PUSH) => .MEMO_PUSH,
            @intFromEnum(FrameType.SESSION_MIGRATE_CONSUMED) => .SESSION_MIGRATE_CONSUMED,
            @intFromEnum(FrameType.SESSION_REPLICA_OFFER) => .SESSION_REPLICA_OFFER,
            @intFromEnum(FrameType.SESSION_REPLICA_ACK) => .SESSION_REPLICA_ACK,
            @intFromEnum(FrameType.SESSION_REPLICA_REVOKE) => .SESSION_REPLICA_REVOKE,
            @intFromEnum(FrameType.MESSAGE_V2) => .MESSAGE_V2,
            @intFromEnum(FrameType.SESSION_REPLICA_ATTACHMENT_LEASE) => .SESSION_REPLICA_ATTACHMENT_LEASE,
            @intFromEnum(FrameType.OPER_EVENT_V2) => .OPER_EVENT_V2,
            @intFromEnum(FrameType.MESSAGE_V2_ACK) => .MESSAGE_V2_ACK,
            @intFromEnum(FrameType.MEDIA_WS_DATAGRAM) => .MEDIA_WS_DATAGRAM,
            else => null,
        };
    }
};

pub const Type = FrameType;

pub const Capability = enum(u3) {
    frame_signing = 0,
    member_account = 1,
    member_oper_info = 2,
    repair_frames = 3,
    session_replica_v2 = 4,
    secure_relay_v2 = 5,
    session_attachment_lease_v2 = 6,
    event_spine_v2 = 7,

    pub fn bit(self: Capability) u3 {
        return @intFromEnum(self);
    }

    pub fn mask(self: Capability) u8 {
        return @as(u8, 1) << self.bit();
    }
};

pub const cap_frame_signing: u8 = Capability.frame_signing.mask();
pub const cap_member_account: u8 = Capability.member_account.mask();
pub const cap_member_oper_info: u8 = Capability.member_oper_info.mask();
pub const cap_repair_frames: u8 = Capability.repair_frames.mask();
pub const cap_session_replica_v2: u8 = Capability.session_replica_v2.mask();
pub const cap_secure_relay_v2: u8 = Capability.secure_relay_v2.mask();
pub const cap_session_attachment_lease_v2: u8 = Capability.session_attachment_lease_v2.mask();
pub const cap_event_spine_v2: u8 = Capability.event_spine_v2.mask();

pub const CapabilitySpec = struct {
    cap: Capability,
    token: []const u8,
    summary: []const u8,

    pub fn bit(self: CapabilitySpec) u3 {
        return self.cap.bit();
    }

    pub fn mask(self: CapabilitySpec) u8 {
        return self.cap.mask();
    }
};

pub const capability_catalog = [_]CapabilitySpec{
    .{
        .cap = .frame_signing,
        .token = "frame-signing",
        .summary = "Signed-frame envelopes for direct-owned state, oper-trust facts, and repair frames.",
    },
    .{
        .cap = .member_account,
        .token = "member-account",
        .summary = "Optional account fields on membership and nick-change propagation.",
    },
    .{
        .cap = .member_oper_info,
        .token = "member-oper-info",
        .summary = "Secured-only real-host and certificate fingerprint propagation for oper-visible identity.",
    },
    .{
        .cap = .repair_frames,
        .token = "repair-frames",
        .summary = "Merkle-guided anti-entropy repair summary, request, and response frames.",
    },
    .{
        .cap = .session_replica_v2,
        .token = "session-replica-v2",
        .summary = "Secured signed OFFER, ACK, and REVOKE transport for reusable session replicas.",
    },
    .{
        .cap = .secure_relay_v2,
        .token = "secure-relay-v2",
        .summary = "Secured multi-hop user relay with immutable origin-signed routing scope.",
    },
    .{
        .cap = .session_attachment_lease_v2,
        .token = "session-attachment-lease-v2",
        .summary = "Secured short-lived positive attachment evidence for SESSION_REPLICA v2.",
    },
    .{
        .cap = .event_spine_v2,
        .token = "event-spine-v2",
        .summary = "Secured multi-hop operator events with immutable origin signatures.",
    },
};

pub fn capabilitySpec(cap: Capability) CapabilitySpec {
    inline for (capability_catalog) |entry| {
        if (entry.cap == cap) return entry;
    }
    unreachable;
}

pub fn capabilityByToken(token: []const u8) ?CapabilitySpec {
    inline for (capability_catalog) |entry| {
        if (std.mem.eql(u8, entry.token, token)) return entry;
    }
    return null;
}

pub const FrameFamily = enum {
    handshake,
    crdt,
    membership,
    relay,
    oper,
    control,
    repair,
    notification,
    session,
    /// Opaque browser Cadence binary media cascade (never re-encoded).
    media,

    pub fn token(self: FrameFamily) []const u8 {
        return switch (self) {
            .handshake => "handshake",
            .crdt => "crdt",
            .membership => "membership",
            .relay => "relay",
            .oper => "oper",
            .control => "control",
            .repair => "repair",
            .notification => "notification",
            .session => "session",
            .media => "media",
        };
    }
};

pub const FrameAuth = enum {
    unsigned,
    signable,
    signed,
    secured_signed,

    pub fn token(self: FrameAuth) []const u8 {
        return switch (self) {
            .unsigned => "unsigned",
            .signable => "signable",
            .signed => "signed",
            .secured_signed => "secured-signed",
        };
    }
};

pub const FrameSpec = struct {
    frame_type: FrameType,
    token: []const u8,
    family: FrameFamily,
    auth: FrameAuth,
    capability_mask: u8 = 0,
    summary: []const u8,
};

pub const frame_catalog = [_]FrameSpec{
    .{ .frame_type = .HANDSHAKE, .token = "HANDSHAKE", .family = .handshake, .auth = .unsigned, .summary = "Exchanges node id, epoch, server name, description, and negotiated S2S capabilities." },
    .{ .frame_type = .BURST, .token = "BURST", .family = .crdt, .auth = .unsigned, .summary = "Initial serialized channel CRDT state burst." },
    .{ .frame_type = .DELTA, .token = "DELTA", .family = .crdt, .auth = .unsigned, .summary = "Incremental channel CRDT delta." },
    .{ .frame_type = .GOSSIP, .token = "GOSSIP", .family = .membership, .auth = .unsigned, .summary = "Ripple membership and suspicion gossip payload." },
    .{ .frame_type = .PING, .token = "PING", .family = .control, .auth = .unsigned, .summary = "Liveness probe; answered with a matching PONG payload." },
    .{ .frame_type = .PONG, .token = "PONG", .family = .control, .auth = .unsigned, .summary = "Liveness probe response." },
    .{ .frame_type = .QUIT, .token = "QUIT", .family = .control, .auth = .unsigned, .summary = "Remote peer close notification." },
    .{ .frame_type = .MEMBERSHIP, .token = "MEMBERSHIP", .family = .membership, .auth = .signable, .summary = "Channel-member route fact; optional account and oper-info extensions are capability-gated." },
    .{ .frame_type = .MESSAGE, .token = "MESSAGE", .family = .relay, .auth = .signed, .summary = "Cross-node PRIVMSG, NOTICE, TAGMSG, DATA, and WHISPER relay with self-contained origin signature." },
    .{ .frame_type = .OPER_GRANT, .token = "OPER_GRANT", .family = .oper, .auth = .secured_signed, .summary = "Cross-mesh operator authorization grant verified against the secured peer identity." },
    .{ .frame_type = .CHANNEL_MODE_FLAGS, .token = "CHANNEL_MODE_FLAGS", .family = .membership, .auth = .signable, .summary = "Boolean channel-mode flag fact." },
    .{ .frame_type = .CHANNEL_LIST, .token = "CHANNEL_LIST", .family = .membership, .auth = .signable, .summary = "Channel list-mode fact for ban, exception, and invite-exception lists." },
    .{ .frame_type = .CHANNEL_PROP, .token = "CHANNEL_PROP", .family = .membership, .auth = .signed, .summary = "IRCX channel property LWW fact with multi-hop origin signature." },
    .{ .frame_type = .TOPIC, .token = "TOPIC", .family = .membership, .auth = .signable, .summary = "Channel topic fact." },
    .{ .frame_type = .NICKCHANGE, .token = "NICKCHANGE", .family = .membership, .auth = .signable, .summary = "Remote nick-change fact; optional account extension is capability-gated." },
    .{ .frame_type = .CHANNEL_MODE_STATE, .token = "CHANNEL_MODE_STATE", .family = .membership, .auth = .signable, .summary = "Parameter and IRCX channel-mode state snapshot." },
    .{ .frame_type = .SESSION_MIGRATE, .token = "SESSION_MIGRATE", .family = .relay, .auth = .signed, .summary = "Signed session-migration capsule for live reclaim on the owning node." },
    .{ .frame_type = .ENTITY_PROP, .token = "ENTITY_PROP", .family = .membership, .auth = .signed, .summary = "IRCX user/member property LWW fact with kind-tagged multi-hop origin signature." },
    .{ .frame_type = .CLONE_COUNT, .token = "CLONE_COUNT", .family = .notification, .auth = .unsigned, .summary = "Per-node clone-count gossip using salted IP hashes." },
    .{ .frame_type = .OPER_EVENT, .token = "OPER_EVENT", .family = .oper, .auth = .signed, .summary = "Network-wide Event-Spine operator notification." },
    .{ .frame_type = .OBSERVE_EVENT, .token = "OBSERVE_EVENT", .family = .oper, .auth = .signed, .summary = "Network-wide operator OBSERVE lifecycle record." },
    .{ .frame_type = .KILL, .token = "KILL", .family = .oper, .auth = .signed, .summary = "Targeted cross-mesh operator KILL command." },
    .{ .frame_type = .WARD, .token = "WARD", .family = .oper, .auth = .signed, .summary = "Network-wide Warden mesh-ban convergence record." },
    .{ .frame_type = .RESYNC, .token = "RESYNC", .family = .control, .auth = .unsigned, .summary = "Full-state resync request after hot-upgrade link preservation." },
    .{ .frame_type = .REPAIR_SUMMARY, .token = "REPAIR_SUMMARY", .family = .repair, .auth = .signed, .capability_mask = cap_repair_frames, .summary = "Merkle/RBSR anti-entropy summary." },
    .{ .frame_type = .REPAIR_REQUEST, .token = "REPAIR_REQUEST", .family = .repair, .auth = .signed, .capability_mask = cap_repair_frames, .summary = "Request for CRDT records whose hashes differ from a repair summary." },
    .{ .frame_type = .REPAIR_RESPONSE, .token = "REPAIR_RESPONSE", .family = .repair, .auth = .signed, .capability_mask = cap_repair_frames, .summary = "Repair records that backfill requested CRDT entities." },
    .{ .frame_type = .MEMO_PUSH, .token = "MEMO_PUSH", .family = .notification, .auth = .secured_signed, .summary = "Secured-only Web Push hint for offline memo delivery." },
    .{ .frame_type = .SESSION_MIGRATE_CONSUMED, .token = "SESSION_MIGRATE_CONSUMED", .family = .relay, .auth = .signed, .summary = "Converges a successful session claim and prevents stale migration resurrection." },
    .{ .frame_type = .SESSION_REPLICA_OFFER, .token = "SESSION_REPLICA_OFFER", .family = .session, .auth = .secured_signed, .capability_mask = cap_session_replica_v2, .summary = "SESSION_REPLICA v2 signed upsert offer." },
    .{ .frame_type = .SESSION_REPLICA_ACK, .token = "SESSION_REPLICA_ACK", .family = .session, .auth = .secured_signed, .capability_mask = cap_session_replica_v2, .summary = "SESSION_REPLICA v2 signed acknowledgment and route observation." },
    .{ .frame_type = .SESSION_REPLICA_REVOKE, .token = "SESSION_REPLICA_REVOKE", .family = .session, .auth = .secured_signed, .capability_mask = cap_session_replica_v2, .summary = "SESSION_REPLICA v2 signed removal tombstone." },
    .{ .frame_type = .MESSAGE_V2, .token = "MESSAGE_V2", .family = .relay, .auth = .secured_signed, .capability_mask = cap_secure_relay_v2, .summary = "Secured multi-hop user relay with immutable origin signature and routing scope." },
    .{ .frame_type = .SESSION_REPLICA_ATTACHMENT_LEASE, .token = "SESSION_REPLICA_ATTACHMENT_LEASE", .family = .session, .auth = .secured_signed, .capability_mask = cap_session_replica_v2 | cap_session_attachment_lease_v2, .summary = "SESSION_REPLICA v2 signed positive attachment lease." },
    .{ .frame_type = .OPER_EVENT_V2, .token = "OPER_EVENT_V2", .family = .oper, .auth = .secured_signed, .capability_mask = cap_event_spine_v2, .summary = "Secured multi-hop Event Spine notification with immutable origin signature." },
    .{ .frame_type = .MESSAGE_V2_ACK, .token = "MESSAGE_V2_ACK", .family = .relay, .auth = .secured_signed, .capability_mask = cap_secure_relay_v2, .summary = "Secured hop receipt for an admitted MESSAGE_V2 RelayId." },
    .{ .frame_type = .MEDIA_WS_DATAGRAM, .token = "MEDIA_WS_DATAGRAM", .family = .media, .auth = .secured_signed, .summary = "Origin-only cascade of an already-validated browser Cadence WS media datagram." },
};

pub fn frameSpec(frame_type: FrameType) FrameSpec {
    inline for (frame_catalog) |entry| {
        if (entry.frame_type == frame_type) return entry;
    }
    unreachable;
}

pub fn frameSpecByTag(tag_value: u8) ?FrameSpec {
    const frame_type = FrameType.fromTag(tag_value) orelse return null;
    return frameSpec(frame_type);
}

pub fn frameSpecByToken(token: []const u8) ?FrameSpec {
    inline for (frame_catalog) |entry| {
        if (std.mem.eql(u8, entry.token, token)) return entry;
    }
    return null;
}

pub const Frame = struct {
    frame_type: FrameType,
    payload: []const u8,
};

pub fn encodedLen(payload_len: usize) EncodeError!usize {
    if (payload_len > std.math.maxInt(u32)) return error.PayloadTooLarge;
    return header_len + payload_len;
}

pub fn encode(frame_type: FrameType, payload: []const u8, out: []u8) EncodeError![]const u8 {
    const total = try encodedLen(payload.len);
    if (out.len < total) return error.BufferTooSmall;

    out[0] = frame_type.tag();
    std.mem.writeInt(u32, out[1..][0..length_len], @intCast(payload.len), endian);
    @memcpy(out[header_len..total], payload);
    return out[0..total];
}

pub const Decoder = struct {
    allocator: std.mem.Allocator,
    max_frame_size: usize,
    accumulator: std.ArrayList(u8) = .empty,
    payload_buf: std.ArrayList(u8) = .empty,

    pub fn init(allocator: std.mem.Allocator, max_frame_size: usize) Decoder {
        return .{
            .allocator = allocator,
            .max_frame_size = max_frame_size,
        };
    }

    pub fn deinit(self: *Decoder) void {
        self.accumulator.deinit(self.allocator);
        self.payload_buf.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn reset(self: *Decoder) void {
        self.accumulator.clearRetainingCapacity();
        self.payload_buf.clearRetainingCapacity();
    }

    pub fn feed(self: *Decoder, bytes: []const u8) DecodeError!void {
        try self.accumulator.appendSlice(self.allocator, bytes);
    }

    pub fn decode(self: *Decoder, bytes: []const u8) DecodeError!?Frame {
        try self.feed(bytes);
        return try self.next();
    }

    /// Returns null until a complete frame is buffered.
    ///
    /// The returned payload is owned by the decoder and remains valid until the
    /// next successful `next`, `decode`, `reset`, or `deinit` call.
    pub fn next(self: *Decoder) DecodeError!?Frame {
        // Loop so an unknown/newer frame tag is skipped (not fatal) and we go
        // on to return the next KNOWN frame in the buffer.
        while (true) {
            if (self.accumulator.items.len < header_len) return null;

            const tag_byte = self.accumulator.items[0];
            const payload_len_u32 = std.mem.readInt(u32, self.accumulator.items[1..][0..length_len], endian);
            const payload_len: usize = @intCast(payload_len_u32);
            if (payload_len > std.math.maxInt(usize) - header_len) return error.OversizeFrame;

            const total = header_len + payload_len;
            if (total > self.max_frame_size) return error.OversizeFrame;
            if (self.accumulator.items.len < total) return null;

            const frame_type = FrameType.fromTag(tag_byte) orelse {
                // Unknown/newer frame tag. The frame is still length-delimited
                // (and bounded by max_frame_size above), so skip it cleanly
                // instead of tearing the whole secured link down — that
                // teardown is what flaps the mesh during a rolling upgrade.
                // Emitting any new frame type stays handshake-cap-gated, so a
                // peer only sends a type it knows the far side understands;
                // this just makes the receiver forward-tolerant.
                self.discardPrefix(total);
                continue;
            };

            try self.payload_buf.resize(self.allocator, payload_len);
            @memcpy(self.payload_buf.items, self.accumulator.items[header_len..total]);
            self.discardPrefix(total);

            return .{
                .frame_type = frame_type,
                .payload = self.payload_buf.items,
            };
        }
    }

    /// Call at EOF when no more bytes are expected.
    pub fn finish(self: *Decoder) DecodeError!void {
        if (self.accumulator.items.len != 0) return error.Truncated;
    }

    fn discardPrefix(self: *Decoder, count: usize) void {
        std.debug.assert(count <= self.accumulator.items.len);
        const remaining = self.accumulator.items.len - count;
        if (remaining != 0) {
            std.mem.copyForwards(u8, self.accumulator.items[0..remaining], self.accumulator.items[count..]);
        }
        self.accumulator.shrinkRetainingCapacity(remaining);
    }
};

const testing = std.testing;

test "encode/decode round-trip each type" {
    const allocator = testing.allocator;

    inline for (frame_catalog) |spec| {
        const frame_type = spec.frame_type;
        const payload = "undertow s2s payload";
        var encoded: [header_len + payload.len]u8 = undefined;
        const bytes = try encode(frame_type, payload, &encoded);

        try testing.expectEqual(frame_type.tag(), bytes[0]);
        try testing.expectEqual(@as(u32, payload.len), std.mem.readInt(u32, bytes[1..][0..length_len], endian));

        var decoder = Decoder.init(allocator, default_max_frame_size);
        defer decoder.deinit();

        try decoder.feed(bytes);
        const frame = (try decoder.next()).?;
        try testing.expectEqual(frame_type, frame.frame_type);
        try testing.expectEqualSlices(u8, payload, frame.payload);
        try testing.expectEqual(@as(?Frame, null), try decoder.next());
        try decoder.finish();
    }
}

test "partial streamed decode reassembles frames" {
    const allocator = testing.allocator;
    const first_payload = "burst-001";
    const second_payload = "delta-002-with-more-bytes";
    var first_buf: [header_len + first_payload.len]u8 = undefined;
    var second_buf: [header_len + second_payload.len]u8 = undefined;
    const first = try encode(.BURST, first_payload, &first_buf);
    const second = try encode(.DELTA, second_payload, &second_buf);

    var decoder = Decoder.init(allocator, default_max_frame_size);
    defer decoder.deinit();

    try decoder.feed(first[0..2]);
    try testing.expectEqual(@as(?Frame, null), try decoder.next());
    try decoder.feed(first[2..header_len]);
    try testing.expectEqual(@as(?Frame, null), try decoder.next());
    try decoder.feed(first[header_len..]);

    const frame1 = (try decoder.next()).?;
    try testing.expectEqual(FrameType.BURST, frame1.frame_type);
    try testing.expectEqualSlices(u8, first_payload, frame1.payload);
    try testing.expectEqual(@as(?Frame, null), try decoder.next());

    var pos: usize = 0;
    while (pos < second.len) {
        const end = @min(pos + 3, second.len);
        try decoder.feed(second[pos..end]);
        pos = end;
    }

    const frame2 = (try decoder.next()).?;
    try testing.expectEqual(FrameType.DELTA, frame2.frame_type);
    try testing.expectEqualSlices(u8, second_payload, frame2.payload);
    try decoder.finish();
}

test "multiple complete frames drain in order" {
    const allocator = testing.allocator;
    const ping_payload = "ping";
    const pong_payload = "pong";
    var ping_buf: [header_len + ping_payload.len]u8 = undefined;
    var pong_buf: [header_len + pong_payload.len]u8 = undefined;
    const ping = try encode(.PING, ping_payload, &ping_buf);
    const pong = try encode(.PONG, pong_payload, &pong_buf);

    var decoder = Decoder.init(allocator, default_max_frame_size);
    defer decoder.deinit();

    try decoder.feed(ping);
    try decoder.feed(pong);

    const frame1 = (try decoder.next()).?;
    try testing.expectEqual(FrameType.PING, frame1.frame_type);
    try testing.expectEqualSlices(u8, ping_payload, frame1.payload);

    const frame2 = (try decoder.next()).?;
    try testing.expectEqual(FrameType.PONG, frame2.frame_type);
    try testing.expectEqualSlices(u8, pong_payload, frame2.payload);

    try testing.expectEqual(@as(?Frame, null), try decoder.next());
    try decoder.finish();
}

test "oversize rejected" {
    const allocator = testing.allocator;
    const payload = "abcd";
    var encoded: [header_len + payload.len]u8 = undefined;
    const bytes = try encode(.GOSSIP, payload, &encoded);

    var decoder = Decoder.init(allocator, header_len + payload.len - 1);
    defer decoder.deinit();

    try decoder.feed(bytes);
    try testing.expectError(error.OversizeFrame, decoder.next());
}

test "truncated handled" {
    const allocator = testing.allocator;

    var decoder = Decoder.init(allocator, default_max_frame_size);
    defer decoder.deinit();

    try decoder.feed(&.{@intFromEnum(FrameType.HANDSHAKE)});
    try testing.expectEqual(@as(?Frame, null), try decoder.next());
    try testing.expectError(error.Truncated, decoder.finish());

    decoder.reset();
    var header: [header_len]u8 = undefined;
    header[0] = @intFromEnum(FrameType.QUIT);
    std.mem.writeInt(u32, header[1..][0..length_len], 3, endian);
    try decoder.feed(&header);
    try testing.expectEqual(@as(?Frame, null), try decoder.next());
    try testing.expectError(error.Truncated, decoder.finish());
}

test "unknown frame type is skipped, not fatal (forward compatibility)" {
    const allocator = testing.allocator;

    // A lone unknown tag (0xff, zero payload) is skipped: next() drains it and
    // reports "no complete known frame" rather than tearing the link down.
    {
        var lone = [_]u8{ 0xff, 0, 0, 0, 0 };
        var decoder = Decoder.init(allocator, default_max_frame_size);
        defer decoder.deinit();
        try decoder.feed(&lone);
        try testing.expect((try decoder.next()) == null);
    }

    // An unknown frame WITH a payload, sandwiched between two known frames:
    // both known frames must still decode in order, the unknown one skipped.
    {
        var buf: [256]u8 = undefined;
        var decoder = Decoder.init(allocator, default_max_frame_size);
        defer decoder.deinit();

        const a = try encode(.PING, "first", &buf);
        try decoder.feed(a);
        // Unknown tag 0xF0 with a 3-byte payload, hand-framed.
        var unknown = [_]u8{ 0xF0, 3, 0, 0, 0, 'x', 'y', 'z' };
        try decoder.feed(&unknown);
        var buf2: [256]u8 = undefined;
        const c = try encode(.PONG, "third", &buf2);
        try decoder.feed(c);

        const f1 = (try decoder.next()).?;
        try testing.expectEqual(FrameType.PING, f1.frame_type);
        try testing.expectEqualSlices(u8, "first", f1.payload);
        const f2 = (try decoder.next()).?;
        try testing.expectEqual(FrameType.PONG, f2.frame_type);
        try testing.expectEqualSlices(u8, "third", f2.payload);
        try testing.expect((try decoder.next()) == null);
    }

    // An unknown frame whose length exceeds max_frame_size is still rejected as
    // oversize (the bound is enforced before the skip).
    {
        var oversize = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff };
        var decoder = Decoder.init(allocator, 64);
        defer decoder.deinit();
        try decoder.feed(&oversize);
        try testing.expectError(error.OversizeFrame, decoder.next());
    }
}

test "encode rejects undersized output buffer" {
    var short: [header_len - 1]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, encode(.PING, "", &short));
}

test "no leak when accumulator owns partial bytes" {
    const allocator = testing.allocator;
    const payload = "partial";
    var encoded: [header_len + payload.len]u8 = undefined;
    const bytes = try encode(.HANDSHAKE, payload, &encoded);

    var decoder = Decoder.init(allocator, default_max_frame_size);
    defer decoder.deinit();

    try decoder.feed(bytes[0 .. bytes.len - 1]);
    try testing.expectEqual(@as(?Frame, null), try decoder.next());
}

test "capability catalog exposes stable wire bits" {
    try testing.expectEqual(@as(u8, 0x01), cap_frame_signing);
    try testing.expectEqual(@as(u8, 0x02), cap_member_account);
    try testing.expectEqual(@as(u8, 0x04), cap_member_oper_info);
    try testing.expectEqual(@as(u8, 0x08), cap_repair_frames);
    try testing.expectEqual(@as(u8, 0x10), cap_session_replica_v2);
    try testing.expectEqual(@as(u8, 0x20), cap_secure_relay_v2);
    try testing.expectEqual(@as(u8, 0x40), cap_session_attachment_lease_v2);
    try testing.expectEqual(@as(u8, 0x80), cap_event_spine_v2);

    try testing.expectEqual(@as(u3, 0), capabilitySpec(.frame_signing).bit());
    try testing.expectEqual(@as(u3, 1), capabilityByToken("member-account").?.bit());
    try testing.expectEqual(@as(u3, 4), capabilityByToken("session-replica-v2").?.bit());
    try testing.expectEqual(@as(u3, 5), capabilityByToken("secure-relay-v2").?.bit());
    try testing.expectEqual(@as(u3, 6), capabilityByToken("session-attachment-lease-v2").?.bit());
    try testing.expectEqual(@as(u3, 7), capabilityByToken("event-spine-v2").?.bit());
    try testing.expect(capabilityByToken("does-not-exist") == null);
}

test "frame catalog covers every known tag exactly once" {
    var seen = std.mem.zeroes([256]bool);
    inline for (frame_catalog) |spec| {
        const tag_value = spec.frame_type.tag();
        try testing.expect(!seen[tag_value]);
        seen[tag_value] = true;
        try testing.expectEqual(spec.frame_type, FrameType.fromTag(tag_value).?);
        try testing.expectEqual(spec.frame_type, frameSpec(spec.frame_type).frame_type);
        try testing.expectEqual(spec.frame_type, frameSpecByTag(tag_value).?.frame_type);
        try testing.expectEqual(spec.frame_type, frameSpecByToken(spec.token).?.frame_type);
    }

    var tag: usize = 0;
    while (tag <= std.math.maxInt(u8)) : (tag += 1) {
        if (FrameType.fromTag(@intCast(tag))) |frame_type| {
            try testing.expect(seen[frame_type.tag()]);
        }
    }
}

test "repair frames are capability catalog gated" {
    inline for (frame_catalog) |spec| {
        if (spec.family == .repair) {
            try testing.expectEqual(cap_repair_frames, spec.capability_mask);
            try testing.expectEqual(FrameAuth.signed, spec.auth);
        }
    }
}

test "session replica v2 frames are secured and capability gated" {
    inline for (frame_catalog) |spec| {
        if (spec.family == .session) {
            const expected = if (spec.frame_type == .SESSION_REPLICA_ATTACHMENT_LEASE)
                cap_session_replica_v2 | cap_session_attachment_lease_v2
            else
                cap_session_replica_v2;
            try testing.expectEqual(expected, spec.capability_mask);
            try testing.expectEqual(FrameAuth.secured_signed, spec.auth);
        }
    }
    try testing.expectEqual(FrameType.SESSION_REPLICA_OFFER, frameSpecByToken("SESSION_REPLICA_OFFER").?.frame_type);
    try testing.expectEqual(FrameType.SESSION_REPLICA_ACK, frameSpecByTag(0x1f).?.frame_type);
    try testing.expectEqual(FrameType.SESSION_REPLICA_REVOKE, FrameType.fromTag(0x20).?);
    try testing.expectEqual(FrameType.SESSION_REPLICA_ATTACHMENT_LEASE, FrameType.fromTag(0x22).?);
}

test "secure relay v2 frame is secured and capability gated" {
    const spec = frameSpec(.MESSAGE_V2);
    try testing.expectEqual(FrameFamily.relay, spec.family);
    try testing.expectEqual(FrameAuth.secured_signed, spec.auth);
    try testing.expectEqual(cap_secure_relay_v2, spec.capability_mask);
    try testing.expectEqual(FrameType.MESSAGE_V2, frameSpecByTag(0x21).?.frame_type);
    try testing.expectEqual(FrameType.MESSAGE_V2, frameSpecByToken("MESSAGE_V2").?.frame_type);
}

test "event spine v2 frame is secured and capability gated" {
    const spec = frameSpec(.OPER_EVENT_V2);
    try testing.expectEqual(FrameFamily.oper, spec.family);
    try testing.expectEqual(FrameAuth.secured_signed, spec.auth);
    try testing.expectEqual(cap_event_spine_v2, spec.capability_mask);
    try testing.expectEqual(FrameType.OPER_EVENT_V2, frameSpecByTag(0x23).?.frame_type);
    try testing.expectEqual(FrameType.OPER_EVENT_V2, frameSpecByToken("OPER_EVENT_V2").?.frame_type);
}

test "media ws datagram frame is secured media family" {
    const spec = frameSpec(.MEDIA_WS_DATAGRAM);
    try testing.expectEqual(FrameFamily.media, spec.family);
    try testing.expectEqual(FrameAuth.secured_signed, spec.auth);
    try testing.expectEqual(@as(u8, 0), spec.capability_mask);
    try testing.expectEqual(FrameType.MEDIA_WS_DATAGRAM, frameSpecByTag(0x25).?.frame_type);
    try testing.expectEqual(FrameType.MEDIA_WS_DATAGRAM, frameSpecByToken("MEDIA_WS_DATAGRAM").?.frame_type);
}
