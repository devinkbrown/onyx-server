// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-mesh-link resume snapshot — the wire format carried across a Helix UPGRADE
//! so an ESTABLISHED secured s2s (mesh) link keeps its encrypted record stream
//! flowing on the successor WITHOUT re-dialing or re-running the AKE. The socket
//! fd survives execve (CLOEXEC cleared); this carries the crypto + framing state
//! that pairs with it so the PEER never sees a drop (no netsplit, no +Y churn).
//!
//! One snapshot is sealed into a `.s2s_link` capsule per carried secured link.
//! `fd` re-attaches the inherited socket. Since schema v4 the link's converged
//! remote-member ROSTER is carried too: the successor primes its fresh route
//! table from it BEFORE sending RESYNC, so the peer's re-burst of the same
//! members dedups to `.unchanged` instead of re-announcing every surviving
//! remote member to local clients as a spurious JOIN — and NAMES for remote
//! members stays correct even before the re-burst lands. The RESYNC still runs
//! and still wins LWW on anything that changed during the swap; the roster is a
//! PRIME, not a replacement for reconvergence. (Pre-v4 capsules carried no
//! roster: the successor stood the inner link up with an empty replica and the
//! RESYNC refilled it, which is what re-announced every member as `.joined`.)
//!
//! SECURITY: the encoded bytes contain the live Mooring directional record keys.
//! They only ever live inside the sealed memfd arena inherited by the successor —
//! never on disk.
//!
//! Wire format (all integers little-endian):
//!   [i32 fd]
//!   [u8 role]            0 = initiator, 1 = responder (outer Mooring role)
//!   [u8 s2s_initiator]   1 if THIS node dialed the link (collision resolution)
//!   [N established]      Established.serialized_len bytes: record keys + peer id
//!                        (schema v1 blobs are 4 bytes shorter here — they predate
//!                         the trailing `admitted_frame_families`; see `decode`)
//!   [u64 send_counter][u64 recv_counter][u64 feed_seq]
//!   inner peer_link header:
//!     [u64 local_epoch][u64 remote_epoch][u32 send_credit][u32 pending_credit]
//!     [u64 next_out_seq][u64 next_in_seq][u64 last_acked]
//!   inner identity/caps:
//!     [u64 remote_node_id][u64 remote_epoch_ms][u8 caps][u8 caps_ext]
//!                                                        (caps bit0 signing, bit1
//!                                                          account, bit2 oper_info,
//!                                                          bit3 repair_frames,
//!                                                          bit4 session_replica_v2,
//!                                                          bit5 secure_relay_v2,
//!                                                          bit6 attachment_lease_v2,
//!                                                          bit7 event_spine_v2;
//!                                                         caps_ext bit0 relay-v2.1
//!                                                                  bit1 ACK confirm
//!                                                         schema + ACK support)
//!   [u16 len][remote_name]
//!   [u16 len][connect_addr] raw sockaddr.in6 of a proven dial target (either direction)
//!   [u32 len][rec_inbuf]    partial inbound record buffered at export
//!   [u32 len][pending_out]  sealed records queued but not yet on the wire
//!   [u32 roster_count][u32 roster_len][roster]   (v4+) the converged remote-
//!                           member roster: `roster_count` self-delimiting
//!                           records (see `RosterMember`), `roster_len` bytes
//!                           total; decode validates the walk fail-closed
const std = @import("std");

const hs = @import("../../crypto/mooring_handshake.zig");
const s2s_frame = @import("../../proto/s2s_frame.zig");

pub const Error = error{
    Truncated,
    TooLong,
    UnsupportedVersion,
    InvalidRole,
    InvalidBoolean,
    UnknownCaps,
    TrailingBytes,
    InvalidRosterMember,
    RosterCountMismatch,
};

pub const est_len = hs.Established.serialized_len;

/// Current `.s2s_link` capsule schema version whose blob layout `encode` writes.
/// The blob carries no inline version — it rides the capsule header — so this
/// MIRRORS the descriptor in `capsule.zig`; bump both together.
pub const schema_version: u16 = 4;

/// Length of the embedded `Established` blob in schema v1 capsules. v2 appended a
/// trailing `admitted_frame_families` (u32) to `Established.serialize`, so a v1
/// blob is exactly a v2 blob minus its last 4 bytes; legacy decode reconstructs
/// `admitted_frame_families = 0` (the correct legacy/open default).
pub const est_len_v1 = est_len - @sizeOf(u32);

pub const cap_signing: u8 = s2s_frame.cap_frame_signing;
pub const cap_account: u8 = s2s_frame.cap_member_account;
pub const cap_oper_info: u8 = s2s_frame.cap_member_oper_info;
pub const cap_repair: u8 = s2s_frame.cap_repair_frames;
pub const cap_session_replica_v2: u8 = s2s_frame.cap_session_replica_v2;
pub const cap_secure_relay_v2: u8 = s2s_frame.cap_secure_relay_v2;
pub const cap_session_attachment_lease_v2: u8 = s2s_frame.cap_session_attachment_lease_v2;
pub const cap_event_spine_v2: u8 = s2s_frame.cap_event_spine_v2;
pub const cap_ext_relay_v2_current: u8 = 1 << 0;
pub const cap_ext_relay_v2_ack_confirm: u8 = 1 << 1;

/// A plain view of one carried secured link. `remote_name`/`rec_inbuf`/`pending_out`
/// borrow the source (encode input) or the decoded buffer (decode output); the
/// fixed-size fields are owned copies.
pub const Snapshot = struct {
    fd: i32 = -1,
    role: u8 = 0,
    s2s_initiator: bool = false,
    /// Serialized `hs.Established` (record keys + base nonces + peer identity).
    established: [est_len]u8 = @splat(0),
    send_counter: u64 = 0,
    recv_counter: u64 = 0,
    feed_seq: u64 = 0,

    // Inner peer_link transport header (seq/ack/credit/epoch continuity).
    pl_local_epoch_ms: u64 = 0,
    pl_remote_epoch_ms: u64 = 0,
    pl_send_credit: u32 = 0,
    pl_pending_credit: u32 = 0,
    pl_next_out_seq: u64 = 0,
    pl_next_in_seq: u64 = 0,
    pl_last_acked: u64 = 0,

    // Inner peer identity/caps.
    remote_node_id: u64 = 0,
    remote_epoch_ms: u64 = 0,
    caps: u8 = 0,
    caps_ext: u8 = 0,
    remote_name: []const u8 = &.{},
    /// Raw `posix.sockaddr.in6` bytes of a proven dial target. An authenticated
    /// reciprocal inbound survivor may inherit the completed outbound target;
    /// this association does not change its handshake initiator direction.
    /// The successor's `[mesh].connect` sweep uses it to recognize preserved
    /// links. Empty when no completed outbound endpoint is known, including
    /// ordinary accepted links without reciprocal endpoint provenance.
    connect_addr: []const u8 = &.{},

    rec_inbuf: []const u8 = &.{},
    pending_out: []const u8 = &.{},

    /// (v4+) The link's converged remote-member roster: `roster_count`
    /// self-delimiting `RosterMember` records, sealed verbatim from the route
    /// table (original nick spelling — including loser-UID aliases — origin
    /// node, status bits, HLC, propagated identity, and the receiver-derived
    /// session token). Borrowed like the other byte fields; `decode` validates
    /// the complete walk fail-closed before returning. Iterate with
    /// `rosterIterator`. Empty on pre-v4 capsules.
    roster: []const u8 = &.{},
    roster_count: u32 = 0,
};

/// One converged remote channel member carried in the v4+ roster block —
/// exactly the per-member tuple `RouteTable.applyMembership` needs so a primed
/// successor makes the peer's RESYNC re-burst dedup to `.unchanged` (no
/// spurious JOIN) while NAMES keeps rendering the member's real identity even
/// before the re-burst lands. All slices borrow the encode input / decode
/// buffer.
pub const RosterMember = struct {
    channel: []const u8,
    nick: []const u8,
    node: u64,
    status: u4,
    hlc: u64,
    username: []const u8 = "",
    realname: []const u8 = "",
    host: []const u8 = "",
    account: []const u8 = "",
    real_host: []const u8 = "",
    certfp: []const u8 = "",
    /// Receiver-derived exact session token (see `route_table.Member`), carried
    /// so exact-token authority survives the swap. Lives only inside the sealed
    /// memfd arena, like the record keys.
    session_token: ?[16]u8 = null,
};

/// Serialize one roster member record onto `out` (the wire format `decode`
/// validates and `RosterIterator` walks). Fail-closed on the same invariants
/// decode enforces so a malformed roster can never be SEALED either.
pub fn appendRosterMember(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    m: RosterMember,
) (Error || std.mem.Allocator.Error)!void {
    if (m.channel.len == 0 or m.nick.len == 0 or m.node == 0) return error.InvalidRosterMember;
    try appendShortSlice(out, allocator, m.channel);
    try appendShortSlice(out, allocator, m.nick);
    try appendInt(out, allocator, u64, m.node);
    try out.append(allocator, @as(u8, m.status));
    try appendInt(out, allocator, u64, m.hlc);
    try appendShortSlice(out, allocator, m.username);
    try appendShortSlice(out, allocator, m.realname);
    try appendShortSlice(out, allocator, m.host);
    try appendShortSlice(out, allocator, m.account);
    try appendShortSlice(out, allocator, m.real_host);
    try appendShortSlice(out, allocator, m.certfp);
    if (m.session_token) |tok| {
        try out.append(allocator, 1);
        try out.appendSlice(allocator, &tok);
    } else {
        try out.append(allocator, 0);
    }
}

/// Walk a validated roster region record by record. `next` returns null at the
/// exact end; truncation, an out-of-range status, a non-boolean token flag, an
/// empty channel/nick, or a zero node id all fail closed.
pub const RosterIterator = struct {
    r: Reader,

    pub fn next(self: *RosterIterator) Error!?RosterMember {
        if (self.r.pos == self.r.buf.len) return null;
        const channel = try self.r.take(try self.r.int(u16));
        const nick = try self.r.take(try self.r.int(u16));
        const node = try self.r.int(u64);
        const status_raw = try self.r.byte();
        if (channel.len == 0 or nick.len == 0 or node == 0) return error.InvalidRosterMember;
        if (status_raw > std.math.maxInt(u4)) return error.InvalidRosterMember;
        const hlc = try self.r.int(u64);
        const username = try self.r.take(try self.r.int(u16));
        const realname = try self.r.take(try self.r.int(u16));
        const host = try self.r.take(try self.r.int(u16));
        const account = try self.r.take(try self.r.int(u16));
        const real_host = try self.r.take(try self.r.int(u16));
        const certfp = try self.r.take(try self.r.int(u16));
        const token: ?[16]u8 = switch (try self.r.byte()) {
            0 => null,
            1 => (try self.r.take(16))[0..16].*,
            else => return error.InvalidRosterMember,
        };
        return .{
            .channel = channel,
            .nick = nick,
            .node = node,
            .status = @intCast(status_raw),
            .hlc = hlc,
            .username = username,
            .realname = realname,
            .host = host,
            .account = account,
            .real_host = real_host,
            .certfp = certfp,
            .session_token = token,
        };
    }
};

pub fn rosterIterator(snap: *const Snapshot) RosterIterator {
    return .{ .r = .{ .buf = snap.roster } };
}

/// Require `bytes` to hold EXACTLY `count` well-formed roster records that
/// consume EXACTLY the region. Run by `decode` (fail-closed before the roster
/// can reach adoption) and by `encode` (so a caller desync can never seal a
/// roster the successor would refuse).
pub fn validateRoster(bytes: []const u8, count: u32) Error!void {
    var it = RosterIterator{ .r = .{ .buf = bytes } };
    var seen: u32 = 0;
    while (try it.next()) |_| {
        if (seen == std.math.maxInt(u32)) return error.RosterCountMismatch;
        seen += 1;
    }
    if (seen != count) return error.RosterCountMismatch;
}

/// Encode `snap` into a freshly-allocated buffer the caller owns. The result
/// contains live record keys — seal it into the arena and never persist it.
pub fn encode(allocator: std.mem.Allocator, snap: Snapshot) (Error || std.mem.Allocator.Error)![]u8 {
    if (snap.remote_name.len > std.math.maxInt(u16)) return error.TooLong;
    if (snap.connect_addr.len > std.math.maxInt(u16)) return error.TooLong;
    if (snap.rec_inbuf.len > std.math.maxInt(u32)) return error.TooLong;
    if (snap.pending_out.len > std.math.maxInt(u32)) return error.TooLong;
    if (snap.roster.len > std.math.maxInt(u32)) return error.TooLong;
    // Never SEAL a roster the successor would refuse: the same walk decode runs.
    try validateRoster(snap.roster, snap.roster_count);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try appendInt(&out, allocator, i32, snap.fd);
    try out.append(allocator, snap.role);
    try out.append(allocator, @intFromBool(snap.s2s_initiator));
    try out.appendSlice(allocator, &snap.established);
    try appendInt(&out, allocator, u64, snap.send_counter);
    try appendInt(&out, allocator, u64, snap.recv_counter);
    try appendInt(&out, allocator, u64, snap.feed_seq);

    try appendInt(&out, allocator, u64, snap.pl_local_epoch_ms);
    try appendInt(&out, allocator, u64, snap.pl_remote_epoch_ms);
    try appendInt(&out, allocator, u32, snap.pl_send_credit);
    try appendInt(&out, allocator, u32, snap.pl_pending_credit);
    try appendInt(&out, allocator, u64, snap.pl_next_out_seq);
    try appendInt(&out, allocator, u64, snap.pl_next_in_seq);
    try appendInt(&out, allocator, u64, snap.pl_last_acked);

    try appendInt(&out, allocator, u64, snap.remote_node_id);
    try appendInt(&out, allocator, u64, snap.remote_epoch_ms);
    try out.append(allocator, snap.caps);
    try out.append(allocator, snap.caps_ext);

    try appendInt(&out, allocator, u16, @intCast(snap.remote_name.len));
    try out.appendSlice(allocator, snap.remote_name);
    try appendInt(&out, allocator, u16, @intCast(snap.connect_addr.len));
    try out.appendSlice(allocator, snap.connect_addr);
    try appendInt(&out, allocator, u32, @intCast(snap.rec_inbuf.len));
    try out.appendSlice(allocator, snap.rec_inbuf);
    try appendInt(&out, allocator, u32, @intCast(snap.pending_out.len));
    try out.appendSlice(allocator, snap.pending_out);
    try appendInt(&out, allocator, u32, snap.roster_count);
    try appendInt(&out, allocator, u32, @intCast(snap.roster.len));
    try out.appendSlice(allocator, snap.roster);

    return out.toOwnedSlice(allocator);
}

/// Decode a snapshot; byte-slice fields borrow `bytes`. `version` is the sealing
/// capsule's schema version (`capsule.Header.version`). A v1 blob predates the
/// trailing `admitted_frame_families` in the embedded `Established` region, so it
/// is 4 bytes shorter there and decodes with `admitted_frame_families = 0`;
/// because the field is appended at the END of `Established.serialize`, a v1 blob
/// is byte-for-byte a v2 blob minus that trailing u32, so every FOLLOWING field
/// still lands at its correct offset. v3 appends the `caps_ext` byte; v4 appends
/// the trailing roster block (pre-v4 blobs decode with an EMPTY roster — the
/// successor then reconverges via RESYNC alone, exactly the pre-bump behavior).
/// Any version outside 1..4 is rejected fail-closed (a too-new blob may have
/// grown an embedded region again and cannot be parsed here).
pub fn decode(bytes: []const u8, version: u16) Error!Snapshot {
    // Every supported predecessor layout is still an authority-bearing Helix
    // image. Version tolerance must not imply tolerance for non-boolean flags,
    // reserved roles, or trailing bytes.
    return decodeInternal(bytes, version, true);
}

/// Decode exactly the current schema emitted by `encode`. Current-generation
/// whole handoffs must not accept reserved roles/capabilities, non-boolean
/// flags, legacy layouts, or bytes after the final bounded field.
pub fn decodeCurrent(bytes: []const u8) Error!Snapshot {
    return decodeInternal(bytes, schema_version, true);
}

fn decodeInternal(bytes: []const u8, version: u16, strict_current: bool) Error!Snapshot {
    var r = Reader{ .buf = bytes };
    var snap = Snapshot{};
    snap.fd = try r.int(i32);
    snap.role = try r.byte();
    if (strict_current and snap.role > 1) return error.InvalidRole;
    const initiator = try r.byte();
    if (strict_current and initiator > 1) return error.InvalidBoolean;
    snap.s2s_initiator = initiator != 0;
    switch (version) {
        1 => {
            @memcpy(snap.established[0..est_len_v1], try r.take(est_len_v1));
            @memset(snap.established[est_len_v1..], 0); // admitted_frame_families = 0
        },
        2, 3, schema_version => @memcpy(&snap.established, try r.take(est_len)),
        // Fail-closed: only v1 and the current schema are parseable here. MAINTENANCE
        // TRAP — each future schema bump that keeps `min_supported = 1` in the capsule
        // descriptor MUST add an explicit legacy arm above for EVERY still-accepted
        // version (not just the newest), or that version's links silently drop across
        // the upgrade (the exact field-shift bug this switch was introduced to fix).
        else => return error.UnsupportedVersion,
    }
    snap.send_counter = try r.int(u64);
    snap.recv_counter = try r.int(u64);
    snap.feed_seq = try r.int(u64);

    snap.pl_local_epoch_ms = try r.int(u64);
    snap.pl_remote_epoch_ms = try r.int(u64);
    snap.pl_send_credit = try r.int(u32);
    snap.pl_pending_credit = try r.int(u32);
    snap.pl_next_out_seq = try r.int(u64);
    snap.pl_next_in_seq = try r.int(u64);
    snap.pl_last_acked = try r.int(u64);

    snap.remote_node_id = try r.int(u64);
    snap.remote_epoch_ms = try r.int(u64);
    snap.caps = try r.byte();
    if (version >= 3) snap.caps_ext = try r.byte();
    const known_caps = cap_signing | cap_account | cap_oper_info | cap_repair |
        cap_session_replica_v2 | cap_secure_relay_v2 |
        cap_session_attachment_lease_v2 | cap_event_spine_v2;
    if (strict_current and snap.caps & ~known_caps != 0) return error.UnknownCaps;
    if (strict_current and snap.caps_ext &
        ~(cap_ext_relay_v2_current | cap_ext_relay_v2_ack_confirm) != 0)
        return error.UnknownCaps;
    if (strict_current and snap.caps_ext & cap_ext_relay_v2_ack_confirm != 0 and
        snap.caps_ext & cap_ext_relay_v2_current == 0) return error.UnknownCaps;
    if (strict_current and snap.caps_ext & cap_ext_relay_v2_current != 0 and
        (snap.caps & (cap_signing | cap_secure_relay_v2)) !=
            (cap_signing | cap_secure_relay_v2)) return error.UnknownCaps;

    snap.remote_name = try r.take(try r.int(u16));
    snap.connect_addr = try r.take(try r.int(u16));
    snap.rec_inbuf = try r.take(try r.int(u32));
    snap.pending_out = try r.take(try r.int(u32));
    if (version >= 4) {
        snap.roster_count = try r.int(u32);
        snap.roster = try r.take(try r.int(u32));
        // Fail-closed BEFORE the roster can reach adoption: the whole region
        // must walk as exactly `roster_count` well-formed records.
        try validateRoster(snap.roster, snap.roster_count);
    }
    if (strict_current and r.pos != bytes.len) return error.TrailingBytes;
    return snap;
}

/// Best-effort recovery of the inherited socket fd from a snapshot blob whose
/// full `decode` failed. The fd is always the fixed leading little-endian i32, so
/// the adoption path can still `close()` it — a decode failure then drops the link
/// cleanly instead of leaking the fd (the fd lives ONLY inside this blob). Returns
/// null if the blob is too short to hold the fd.
pub fn peekFd(bytes: []const u8) ?i32 {
    if (bytes.len < @sizeOf(i32)) return null;
    return std.mem.readInt(i32, bytes[0..@sizeOf(i32)], .little);
}

fn appendInt(out: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime T: type, value: T) std.mem.Allocator.Error!void {
    var le: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &le, value, .little);
    try out.appendSlice(allocator, &le);
}

fn appendShortSlice(out: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8) (Error || std.mem.Allocator.Error)!void {
    if (bytes.len > std.math.maxInt(u16)) return error.TooLong;
    try appendInt(out, allocator, u16, @intCast(bytes.len));
    try out.appendSlice(allocator, bytes);
}

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn byte(self: *Reader) Error!u8 {
        if (self.pos + 1 > self.buf.len) return error.Truncated;
        defer self.pos += 1;
        return self.buf[self.pos];
    }
    fn int(self: *Reader, comptime T: type) Error!T {
        if (self.pos + @sizeOf(T) > self.buf.len) return error.Truncated;
        defer self.pos += @sizeOf(T);
        return std.mem.readInt(T, self.buf[self.pos..][0..@sizeOf(T)], .little);
    }
    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (self.pos + n > self.buf.len) return error.Truncated;
        defer self.pos += n;
        return self.buf[self.pos .. self.pos + n];
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "s2s link snapshot round-trips fd, keys, counters, framing header + buffers" {
    const allocator = testing.allocator;
    var snap = Snapshot{
        .fd = 41,
        .role = 1,
        .s2s_initiator = true,
        .send_counter = 12345,
        .recv_counter = 6789,
        .feed_seq = 42,
        .pl_local_epoch_ms = 1000,
        .pl_remote_epoch_ms = 2000,
        .pl_send_credit = 60000,
        .pl_pending_credit = 512,
        .pl_next_out_seq = 88,
        .pl_next_in_seq = 77,
        .pl_last_acked = 66,
        .remote_node_id = 0xDEADBEEFCAFEF00D,
        .remote_epoch_ms = 2000,
        .caps = cap_signing | cap_oper_info | cap_repair | cap_session_replica_v2 | cap_secure_relay_v2 | cap_session_attachment_lease_v2 | cap_event_spine_v2,
        .caps_ext = cap_ext_relay_v2_current | cap_ext_relay_v2_ack_confirm,
        .remote_name = "ircx.us",
        .connect_addr = &@as([28]u8, @splat('\x0a')),
        .rec_inbuf = "\x04\x00\x00\x00partial",
        .pending_out = "sealed-record-bytes",
    };
    for (&snap.established, 0..) |*b, i| b.* = @truncate(i * 3 + 1);

    const bytes = try encode(allocator, snap);
    defer allocator.free(bytes);

    const got = try decode(bytes, schema_version);
    try testing.expectEqual(@as(i32, 41), got.fd);
    try testing.expectEqual(@as(u8, 1), got.role);
    try testing.expect(got.s2s_initiator);
    try testing.expectEqualSlices(u8, &snap.established, &got.established);
    try testing.expectEqual(@as(u64, 12345), got.send_counter);
    try testing.expectEqual(@as(u64, 6789), got.recv_counter);
    try testing.expectEqual(@as(u64, 42), got.feed_seq);
    try testing.expectEqual(@as(u64, 1000), got.pl_local_epoch_ms);
    try testing.expectEqual(@as(u32, 60000), got.pl_send_credit);
    try testing.expectEqual(@as(u64, 88), got.pl_next_out_seq);
    try testing.expectEqual(@as(u64, 77), got.pl_next_in_seq);
    try testing.expectEqual(@as(u64, 66), got.pl_last_acked);
    try testing.expectEqual(@as(u64, 0xDEADBEEFCAFEF00D), got.remote_node_id);
    try testing.expectEqual(cap_signing | cap_oper_info | cap_repair | cap_session_replica_v2 | cap_secure_relay_v2 | cap_session_attachment_lease_v2 | cap_event_spine_v2, got.caps);
    try testing.expectEqual(cap_ext_relay_v2_current | cap_ext_relay_v2_ack_confirm, got.caps_ext);
    try testing.expectEqualStrings("ircx.us", got.remote_name);
    try testing.expectEqualStrings(&@as([28]u8, @splat('\x0a')), got.connect_addr);
    try testing.expectEqualStrings("\x04\x00\x00\x00partial", got.rec_inbuf);
    try testing.expectEqualStrings("sealed-record-bytes", got.pending_out);
}

test "s2s link snapshot decode rejects truncation" {
    try testing.expectError(error.Truncated, decode(&[_]u8{ 1, 0, 0 }, schema_version));
}

test "current s2s decode rejects noncanonical flags capabilities legacy and trailing bytes" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{ .fd = 41, .remote_node_id = 9 });
    defer allocator.free(bytes);
    _ = try decodeCurrent(bytes);

    const bad_role = try allocator.dupe(u8, bytes);
    defer allocator.free(bad_role);
    bad_role[4] = 2;
    try testing.expectError(error.InvalidRole, decodeCurrent(bad_role));
    const bad_bool = try allocator.dupe(u8, bytes);
    defer allocator.free(bad_bool);
    bad_bool[5] = 2;
    try testing.expectError(error.InvalidBoolean, decodeCurrent(bad_bool));

    const trailing = try allocator.alloc(u8, bytes.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..bytes.len], bytes);
    trailing[bytes.len] = 0;
    try testing.expectError(error.TrailingBytes, decodeCurrent(trailing));
    try testing.expectError(error.Truncated, decodeCurrent(bytes[0 .. bytes.len - 1]));
}

/// Byte offset of the embedded `Established` region: `fd`(i32) + `role`(u8) +
/// `s2s_initiator`(u8). The trailing `admitted_frame_families`(u32) that v2 added
/// lives at the END of that region.
const est_field_off: usize = @sizeOf(i32) + 1 + 1;
const caps_ext_field_off_v2: usize = est_field_off + est_len +
    8 + 8 + 8 +
    8 + 8 + 4 + 4 + 8 + 8 + 8 +
    8 + 8 + 1;

/// Synthesize the pre-roster (≤v3) wire image from a current-encode blob by
/// stripping the trailing v4 roster block. Valid only when the encoded roster
/// was EMPTY (the block is then exactly 8 zero bytes: count=0, len=0) — the
/// legacy fixtures below all model rosterless predecessors.
fn stripEmptyRosterBlock(bytes: []const u8) []const u8 {
    std.debug.assert(bytes.len >= 8);
    for (bytes[bytes.len - 8 ..]) |b| std.debug.assert(b == 0);
    return bytes[0 .. bytes.len - 8];
}

test "current s2s decode rejects inconsistent relay-v2 capability combinations" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{
        .fd = 41,
        .remote_node_id = 9,
        .caps = cap_signing | cap_secure_relay_v2,
        .caps_ext = cap_ext_relay_v2_current | cap_ext_relay_v2_ack_confirm,
    });
    defer allocator.free(bytes);
    _ = try decodeCurrent(bytes);

    const confirm_without_current = try allocator.dupe(u8, bytes);
    defer allocator.free(confirm_without_current);
    confirm_without_current[caps_ext_field_off_v2] = cap_ext_relay_v2_ack_confirm;
    try testing.expectError(error.UnknownCaps, decodeCurrent(confirm_without_current));

    const current_without_secure_relay = try allocator.dupe(u8, bytes);
    defer allocator.free(current_without_secure_relay);
    current_without_secure_relay[caps_ext_field_off_v2 - 1] = cap_signing;
    try testing.expectError(error.UnknownCaps, decodeCurrent(current_without_secure_relay));

    const current_without_signing = try allocator.dupe(u8, bytes);
    defer allocator.free(current_without_signing);
    current_without_signing[caps_ext_field_off_v2 - 1] = cap_secure_relay_v2;
    try testing.expectError(error.UnknownCaps, decodeCurrent(current_without_signing));
}

test "s2s link snapshot v2 round-trip preserves admitted_frame_families" {
    const allocator = testing.allocator;
    var snap = Snapshot{
        .fd = 7,
        .send_counter = 900,
        .recv_counter = 800,
        .caps = cap_signing,
        .remote_name = "peer.example",
        .rec_inbuf = "inbuf",
        .pending_out = "pending",
    };
    // Fill the Established blob with a recognizable pattern and stamp a NON-ZERO
    // admitted_frame_families into its trailing u32 (the v2-only field).
    for (&snap.established, 0..) |*b, i| b.* = @truncate(i + 5);
    std.mem.writeInt(u32, snap.established[est_len - 4 ..][0..4], 0x1122_3344, .little);

    const bytes = try encode(allocator, snap);
    defer allocator.free(bytes);

    // A real v2 blob predates BOTH the v3 caps_ext byte and the v4 roster block.
    const v3_wire = stripEmptyRosterBlock(bytes);
    var legacy_v2 = try allocator.alloc(u8, v3_wire.len - 1);
    defer allocator.free(legacy_v2);
    @memcpy(legacy_v2[0..caps_ext_field_off_v2], v3_wire[0..caps_ext_field_off_v2]);
    @memcpy(legacy_v2[caps_ext_field_off_v2..], v3_wire[caps_ext_field_off_v2 + 1 ..]);

    const got = try decode(legacy_v2, 2);
    try testing.expectEqualSlices(u8, &snap.established, &got.established);
    try testing.expectEqual(
        @as(u32, 0x1122_3344),
        std.mem.readInt(u32, got.established[est_len - 4 ..][0..4], .little),
    );
    try testing.expectEqual(@as(u64, 900), got.send_counter);
    try testing.expectEqual(@as(u64, 800), got.recv_counter);
    try testing.expectEqualStrings("peer.example", got.remote_name);
    try testing.expectEqualStrings("inbuf", got.rec_inbuf);
    try testing.expectEqualStrings("pending", got.pending_out);
    try testing.expectEqual(@as(u8, 0), got.caps_ext);

    const trailing = try allocator.alloc(u8, legacy_v2.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..legacy_v2.len], legacy_v2);
    trailing[legacy_v2.len] = 0;
    try testing.expectError(error.TrailingBytes, decode(trailing, 2));

    const bad_bool = try allocator.dupe(u8, legacy_v2);
    defer allocator.free(bad_bool);
    bad_bool[5] = 2;
    try testing.expectError(error.InvalidBoolean, decode(bad_bool, 2));
}

test "s2s link snapshot v1 blob decodes with admitted_frame_families=0 and all following fields intact" {
    const allocator = testing.allocator;
    var snap = Snapshot{
        .fd = 33,
        .role = 1,
        .s2s_initiator = true,
        .send_counter = 0xAABBCCDD_00112233,
        .recv_counter = 0x0102030405060708,
        .feed_seq = 4242,
        .pl_local_epoch_ms = 111,
        .pl_remote_epoch_ms = 222,
        .pl_send_credit = 65000,
        .pl_pending_credit = 4096,
        .pl_next_out_seq = 91,
        .pl_next_in_seq = 82,
        .pl_last_acked = 73,
        .remote_node_id = 0xFEEDFACECAFEBEEF,
        .remote_epoch_ms = 3333,
        .caps = cap_signing | cap_account | cap_repair,
        .remote_name = "legacy.peer",
        .connect_addr = &@as([28]u8, @splat('\x0b')),
        .rec_inbuf = "half-record",
        .pending_out = "queued-sealed",
    };
    // Give the Established region a distinct pattern and a non-zero trailing
    // admitted_frame_families so we can prove v1 decode zeroes exactly it.
    for (&snap.established, 0..) |*b, i| b.* = @truncate(i * 7 + 3);
    std.mem.writeInt(u32, snap.established[est_len - 4 ..][0..4], 0x7F00_00FF, .little);

    // Encode current, then synthesize the v1 wire format by stripping the v4
    // roster block and SPLICING OUT the v3 caps_ext byte and the trailing
    // admitted_frame_families(u32) at the end of the Established region —
    // exactly what a pre-bump binary would have produced.
    const current = try encode(allocator, snap);
    defer allocator.free(current);
    const v3_wire = stripEmptyRosterBlock(current);
    var v2 = try allocator.alloc(u8, v3_wire.len - 1);
    defer allocator.free(v2);
    @memcpy(v2[0..caps_ext_field_off_v2], v3_wire[0..caps_ext_field_off_v2]);
    @memcpy(v2[caps_ext_field_off_v2..], v3_wire[caps_ext_field_off_v2 + 1 ..]);
    const cut_at = est_field_off + est_len - 4;
    var v1: std.ArrayList(u8) = .empty;
    defer v1.deinit(allocator);
    try v1.appendSlice(allocator, v2[0..cut_at]);
    try v1.appendSlice(allocator, v2[cut_at + 4 ..]);
    try testing.expectEqual(v2.len - 4, v1.items.len);

    const got = try decode(v1.items, 1);

    // The Established prefix (everything before admitted_frame_families) survives
    // verbatim; the trailing u32 is reconstructed as the legacy/open default 0.
    try testing.expectEqualSlices(u8, snap.established[0..est_len_v1], got.established[0..est_len_v1]);
    try testing.expectEqual(
        @as(u32, 0),
        std.mem.readInt(u32, got.established[est_len - 4 ..][0..4], .little),
    );

    // Every field FOLLOWING the Established region must land at its correct offset.
    try testing.expectEqual(@as(i32, 33), got.fd);
    try testing.expectEqual(@as(u8, 1), got.role);
    try testing.expect(got.s2s_initiator);
    try testing.expectEqual(@as(u64, 0xAABBCCDD_00112233), got.send_counter);
    try testing.expectEqual(@as(u64, 0x0102030405060708), got.recv_counter);
    try testing.expectEqual(@as(u64, 4242), got.feed_seq);
    try testing.expectEqual(@as(u64, 111), got.pl_local_epoch_ms);
    try testing.expectEqual(@as(u64, 222), got.pl_remote_epoch_ms);
    try testing.expectEqual(@as(u32, 65000), got.pl_send_credit);
    try testing.expectEqual(@as(u32, 4096), got.pl_pending_credit);
    try testing.expectEqual(@as(u64, 91), got.pl_next_out_seq);
    try testing.expectEqual(@as(u64, 82), got.pl_next_in_seq);
    try testing.expectEqual(@as(u64, 73), got.pl_last_acked);
    try testing.expectEqual(@as(u64, 0xFEEDFACECAFEBEEF), got.remote_node_id);
    try testing.expectEqual(@as(u64, 3333), got.remote_epoch_ms);
    try testing.expectEqual(cap_signing | cap_account | cap_repair, got.caps);
    try testing.expectEqualStrings("legacy.peer", got.remote_name);
    try testing.expectEqualStrings(&@as([28]u8, @splat('\x0b')), got.connect_addr);
    try testing.expectEqualStrings("half-record", got.rec_inbuf);
    try testing.expectEqualStrings("queued-sealed", got.pending_out);
}

test "s2s link snapshot decode rejects an unknown too-new version fail-closed" {
    const allocator = testing.allocator;
    var snap = Snapshot{ .fd = 5 };
    for (&snap.established, 0..) |*b, i| b.* = @truncate(i);
    const bytes = try encode(allocator, snap);
    defer allocator.free(bytes);
    try testing.expectError(error.UnsupportedVersion, decode(bytes, schema_version + 1));
}

test "peekFd recovers the leading fd even from an otherwise-unparseable blob" {
    // A blob far too short to decode still yields its fd for cleanup.
    var buf: [4]u8 = undefined;
    std.mem.writeInt(i32, &buf, 49, .little);
    try testing.expectEqual(@as(?i32, 49), peekFd(&buf));
    try testing.expectError(error.Truncated, decode(&buf, schema_version));
    // Too short to even hold the fd → null (no bogus close).
    try testing.expectEqual(@as(?i32, null), peekFd(&[_]u8{ 1, 2, 3 }));
}

test "s2s link snapshot v4 capsule carries the converged roster across a Helix upgrade round-trip" {
    const allocator = testing.allocator;

    var roster: std.ArrayList(u8) = .empty;
    defer roster.deinit(allocator);
    const tok: [16]u8 = @splat(0xD7);
    try appendRosterMember(allocator, &roster, .{
        .channel = "#root",
        .nick = "trev",
        .node = 0xB0B,
        .status = 0xF,
        .hlc = 777,
        .username = "trev",
        .realname = "Trevor",
        .host = "cloak.ircx.us",
        .account = "trev",
        .real_host = "10.0.0.7",
        .certfp = "aa:bb:cc",
        .session_token = tok,
    });
    // A minimal identity-less member stored under a collision loser-UID alias.
    try appendRosterMember(allocator, &roster, .{
        .channel = "#undertow",
        .nick = "u1000AAAAA",
        .node = 3,
        .status = 0,
        .hlc = 1,
    });

    var snap = Snapshot{
        .fd = 9,
        .remote_node_id = 4,
        .remote_name = "peer.example",
        .roster = roster.items,
        .roster_count = 2,
    };
    for (&snap.established, 0..) |*b, i| b.* = @truncate(i);

    const bytes = try encode(allocator, snap);
    defer allocator.free(bytes);
    const got = try decodeCurrent(bytes);
    try testing.expectEqual(@as(u32, 2), got.roster_count);
    try testing.expectEqualSlices(u8, roster.items, got.roster);

    var it = rosterIterator(&got);
    const m0 = (try it.next()).?;
    try testing.expectEqualStrings("#root", m0.channel);
    try testing.expectEqualStrings("trev", m0.nick);
    try testing.expectEqual(@as(u64, 0xB0B), m0.node);
    try testing.expectEqual(@as(u4, 0xF), m0.status);
    try testing.expectEqual(@as(u64, 777), m0.hlc);
    try testing.expectEqualStrings("trev", m0.username);
    try testing.expectEqualStrings("Trevor", m0.realname);
    try testing.expectEqualStrings("cloak.ircx.us", m0.host);
    try testing.expectEqualStrings("trev", m0.account);
    try testing.expectEqualStrings("10.0.0.7", m0.real_host);
    try testing.expectEqualStrings("aa:bb:cc", m0.certfp);
    try testing.expectEqualSlices(u8, &tok, &m0.session_token.?);
    const m1 = (try it.next()).?;
    try testing.expectEqualStrings("#undertow", m1.channel);
    try testing.expectEqualStrings("u1000AAAAA", m1.nick);
    try testing.expectEqual(@as(u64, 3), m1.node);
    try testing.expectEqual(@as(u4, 0), m1.status);
    try testing.expectEqual(@as(u64, 1), m1.hlc);
    try testing.expectEqualStrings("", m1.username);
    try testing.expect(m1.session_token == null);
    try testing.expect((try it.next()) == null);

    // Strict current decode still rejects bytes after the roster block.
    const trailing = try allocator.alloc(u8, bytes.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..bytes.len], bytes);
    trailing[bytes.len] = 0;
    try testing.expectError(error.TrailingBytes, decodeCurrent(trailing));
}

test "s2s link snapshot v3 capsule (immediately-prior schema) decodes with an empty roster" {
    const allocator = testing.allocator;
    var snap = Snapshot{
        .fd = 12,
        .role = 1,
        .s2s_initiator = true,
        .send_counter = 5100,
        .recv_counter = 5200,
        .feed_seq = 7,
        .remote_node_id = 0x1234,
        .remote_epoch_ms = 88,
        .caps = cap_signing | cap_secure_relay_v2,
        .caps_ext = cap_ext_relay_v2_current,
        .remote_name = "v3.peer",
        .rec_inbuf = "carry",
        .pending_out = "queued",
    };
    for (&snap.established, 0..) |*b, i| b.* = @truncate(i * 5 + 2);

    // A v3 blob is exactly the v4 wire minus its trailing roster block.
    const current = try encode(allocator, snap);
    defer allocator.free(current);
    const v3_wire = stripEmptyRosterBlock(current);

    const got = try decode(v3_wire, 3);
    try testing.expectEqual(@as(i32, 12), got.fd);
    try testing.expect(got.s2s_initiator);
    try testing.expectEqualSlices(u8, &snap.established, &got.established);
    try testing.expectEqual(@as(u64, 5100), got.send_counter);
    try testing.expectEqual(@as(u64, 5200), got.recv_counter);
    try testing.expectEqual(@as(u64, 0x1234), got.remote_node_id);
    try testing.expectEqual(cap_signing | cap_secure_relay_v2, got.caps);
    try testing.expectEqual(cap_ext_relay_v2_current, got.caps_ext);
    try testing.expectEqualStrings("v3.peer", got.remote_name);
    try testing.expectEqualStrings("carry", got.rec_inbuf);
    try testing.expectEqualStrings("queued", got.pending_out);
    // No roster block in a v3 blob: the successor primes nothing and the RESYNC
    // reconverges alone — the exact pre-bump behavior.
    try testing.expectEqual(@as(u32, 0), got.roster_count);
    try testing.expectEqual(@as(usize, 0), got.roster.len);
    var it = rosterIterator(&got);
    try testing.expect((try it.next()) == null);

    // A v3 decode must NOT tolerate the v4 roster block riding behind it.
    try testing.expectError(error.TrailingBytes, decode(current, 3));
}

test "s2s link snapshot capsule roster decode fails closed on malformed records" {
    const allocator = testing.allocator;

    var roster: std.ArrayList(u8) = .empty;
    defer roster.deinit(allocator);
    try appendRosterMember(allocator, &roster, .{
        .channel = "#c",
        .nick = "n",
        .node = 7,
        .status = 2,
        .hlc = 42,
    });
    const rlen = roster.items.len;

    var snap = Snapshot{ .fd = 3, .remote_node_id = 9, .roster = roster.items, .roster_count = 1 };
    for (&snap.established, 0..) |*b, i| b.* = @truncate(i + 1);
    const bytes = try encode(allocator, snap);
    defer allocator.free(bytes);
    _ = try decodeCurrent(bytes);

    // Layout of the trailing block: [u32 count][u32 len][roster rlen bytes].
    const count_off = bytes.len - rlen - 8;
    const region_off = bytes.len - rlen;

    // (a) A count that does not match the walked records fails closed.
    const bad_count = try allocator.dupe(u8, bytes);
    defer allocator.free(bad_count);
    std.mem.writeInt(u32, bad_count[count_off..][0..4], 2, .little);
    try testing.expectError(error.RosterCountMismatch, decodeCurrent(bad_count));

    // (b) A truncated roster region fails closed.
    try testing.expectError(error.Truncated, decodeCurrent(bytes[0 .. bytes.len - 1]));

    // (c) An out-of-range status byte fails closed. Offset inside the record:
    //     [u16+chan][u16+nick][u64 node] → 2+2 + 2+1 + 8 = 15.
    const bad_status = try allocator.dupe(u8, bytes);
    defer allocator.free(bad_status);
    bad_status[region_off + 15] = 0x10;
    try testing.expectError(error.InvalidRosterMember, decodeCurrent(bad_status));

    // (d) A non-boolean session-token flag (the record's last byte) fails closed.
    const bad_flag = try allocator.dupe(u8, bytes);
    defer allocator.free(bad_flag);
    bad_flag[bytes.len - 1] = 2;
    try testing.expectError(error.InvalidRosterMember, decodeCurrent(bad_flag));
}

test "s2s link snapshot capsule roster refuses to SEAL malformed members" {
    const allocator = testing.allocator;
    var roster: std.ArrayList(u8) = .empty;
    defer roster.deinit(allocator);

    // Empty nick / empty channel / zero node id are unrepresentable rows.
    try testing.expectError(error.InvalidRosterMember, appendRosterMember(allocator, &roster, .{
        .channel = "#c",
        .nick = "",
        .node = 7,
        .status = 0,
        .hlc = 1,
    }));
    try testing.expectError(error.InvalidRosterMember, appendRosterMember(allocator, &roster, .{
        .channel = "",
        .nick = "n",
        .node = 7,
        .status = 0,
        .hlc = 1,
    }));
    try testing.expectError(error.InvalidRosterMember, appendRosterMember(allocator, &roster, .{
        .channel = "#c",
        .nick = "n",
        .node = 0,
        .status = 0,
        .hlc = 1,
    }));
    try testing.expectEqual(@as(usize, 0), roster.items.len);

    // And encode itself re-validates: a count desync can never be sealed.
    try appendRosterMember(allocator, &roster, .{
        .channel = "#c",
        .nick = "n",
        .node = 7,
        .status = 0,
        .hlc = 1,
    });
    const desynced = Snapshot{ .fd = 1, .roster = roster.items, .roster_count = 2 };
    try testing.expectError(error.RosterCountMismatch, encode(allocator, desynced));
}
