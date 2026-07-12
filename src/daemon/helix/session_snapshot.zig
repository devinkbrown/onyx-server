// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-client session snapshot — the wire format carried across a Helix UPGRADE
//! so a registered client can be re-created on the successor.
//!
//! This is the *content* of a per-client capsule field: the identity/state needed
//! to reconstruct a recognizable registered session (nick, realname, account,
//! visible + real host, away, oper + the full oper grant) plus the client's
//! channel memberships (name + member-mode prefixes), which the successor
//! re-joins so the user stays in their channels across the upgrade. The client's
//! socket fd is carried separately (SCM_RIGHTS / inherited fd); this is only the
//! session state that pairs with it. Client-settable umodes are a later increment.
//!
//! Wire format (all integers little-endian):
//!   [u16 len][nick][u16 len][realname][u16 len][account]
//!   [u16 len][real_host][u16 len][host][u16 len][away]
//!   [u8 flags]   bit0=logged_in  bit1=away_active  bit2=is_oper
//!   [i32 fd]     the client's socket fd (inherited across execve), -1 if none
//!   [u16 nchan]  ( [u16 len][name][u8 member-modes] )*   channel memberships
//!   [i64 connected_at_ms][i64 last_message_ms]   OPTIONAL trailing block
//!   [u16 len][caps]   OPTIONAL trailing CAP list (space-separated names)
//!   [u64 oper_priv_bits][u16 len][oper_class][u16 len][oper_title]  OPTIONAL
//!   [u16 len][username]   OPTIONAL trailing USER ident (past the oper grant)
//!   [u8 was_secured]      OPTIONAL trailing secured-flag (past the username)
//!   [u8 tlen][token]      OPTIONAL trailing session reclaim token (past the flag)
//!
//! The oper-grant block (OPTIONAL, written after the caps block) carries the
//! operator's privilege bits (OperPrivileges.toBits — append-only ordinals) plus
//! class + title, so a restored oper keeps its FULL grant and the server-managed
//! +a admin umode derives correctly. Omitting it (pre-grant build) decodes to 0
//! bits → a bare `is_oper` with no privileges, exactly the pre-fix behavior.
//!
//! The trailing signon block carries the client's CLOCK_MONOTONIC signon and
//! last-message timestamps so WHOIS idle/signon survive an in-place UPGRADE.
//! CLOCK_MONOTONIC is system-wide and unaffected by execve, so the predecessor's
//! values stay directly comparable on the successor (same host, same boot). The
//! block is OPTIONAL: a snapshot written by a pre-signon build omits it, and the
//! decoder defaults both to 0 so the successor falls back to "now" — no client is
//! dropped on the single upgrade that crosses this format change.
//!
//! The caps block (also OPTIONAL, written only after the signon block) carries the
//! negotiated IRCv3 CAP set BY NAME — a space-separated list like
//! "echo-message server-time message-tags". Names, not raw bits, because the
//! CapId bit positions shift whenever an upgrade adds/removes/reorders a cap; a
//! name survives that and an unknown name is simply dropped on restore. Omitting
//! it (pre-caps build) decodes to "" so the successor restores no caps — exactly
//! the pre-fix behavior, never a misattributed bit.
//!
//! The secured-flag block (OPTIONAL, one byte, written last — past the username)
//! records whether the connection had a live TLS engine when it was sealed. It is
//! the fail-SAFE join for the successor's adoption path: a client that WAS secured
//! but arrives without a decodable TLS-engine capsule is DROPPED, never adopted as
//! plaintext — a secured socket must never silently fall back to cleartext. It is
//! APPEND-ONLY: a capsule from a pre-flag build omits it and decodes to
//! `was_secured = false`, which is exactly the historical (never-drop) behavior.
//! Because this grows the `.clients` payload, the `.clients` capsule descriptor is
//! bumped to `current_version = 2` (`min_supported = 1` still adopts old capsules;
//! see helix/capsule.zig) and `decode` reads the byte tolerantly.
//!
//! The session-token block (OPTIONAL, `[u8 tlen][tlen bytes]`, written last — past
//! the secured flag) carries the client's 16-byte multi-session reclaim token so a
//! carried connection re-attaches into the SessionStore with the SAME token. It
//! fixes the carried-client-becomes-a-registry-orphan bug: without it every USR2
//! left adopted clients untracked — `SESSION TOKEN` answered "no token", and their
//! eventual disconnect found no registry entry to detach, so the session was
//! permanently un-reclaimable (every deploy invalidated a web client's stored
//! TOKEN/MTOKEN resume). `tlen = 0` means no token was tracked (not logged in);
//! omitting the block entirely (a pre-token v2 build) decodes to an empty token and
//! the successor mints a fresh one via the normal tracking path — a legacy capsule
//! NEVER drops the client. Growing the payload again is why the `.clients`
//! descriptor is at version 3 (capsule.zig).
const std = @import("std");

pub const Error = error{ Truncated, TooLong };

/// One channel membership carried for a client: the channel name + the member's
/// status-mode bits (chanmode.MemberModes.bits).
pub const ChannelMembership = struct {
    name: []const u8,
    modes: u8 = 0,
};

/// A plain, allocation-free view of a client's session state.
pub const Snapshot = struct {
    nick: []const u8 = "",
    realname: []const u8 = "",
    account: []const u8 = "",
    real_host: []const u8 = "",
    host: []const u8 = "",
    away: []const u8 = "",
    /// The client's USER ident. Carried as an OPTIONAL trailing block so a
    /// capsule from a pre-username build decodes it as "" (→ the daemon's
    /// account/"user" fallback in ClientSession.username).
    username: []const u8 = "",
    logged_in: bool = false,
    away_active: bool = false,
    is_oper: bool = false,
    /// True when the connection had a live TLS engine at seal time. Carried as an
    /// OPTIONAL trailing byte so a capsule from a pre-flag build decodes to false
    /// (the historical never-drop behavior). On adopt, a snapshot with
    /// `was_secured = true` that arrives WITHOUT its TLS-engine capsule is dropped
    /// rather than adopted as plaintext — a secured socket never falls back to
    /// cleartext.
    was_secured: bool = false,
    /// The client's 16-byte multi-session reclaim token (sessions.zig `Token`),
    /// carried as an OPTIONAL trailing block so the successor re-tracks the
    /// adopted connection in the SessionStore under the SAME token. Empty = no
    /// token carried (not logged in, or a pre-token capsule) → the successor
    /// mints a fresh token via the normal tracking path.
    session_token: []const u8 = &.{},
    /// The client's socket fd, preserved across execve (CLOEXEC cleared by the
    /// predecessor) so the successor re-attaches the live connection. -1 = none.
    fd: i32 = -1,
    /// Channel memberships to re-join on the successor (ENCODE input only).
    channels: []const ChannelMembership = &.{},
    /// The raw trailing channel-list bytes (DECODE output); walk via `channelIter`.
    channels_blob: []const u8 = "",
    /// CLOCK_MONOTONIC signon timestamp (ms). 0 = unknown (pre-signon snapshot);
    /// the successor falls back to its own "now" when restoring.
    connected_at_ms: i64 = 0,
    /// CLOCK_MONOTONIC last-message timestamp (ms) driving WHOIS idle. 0 = unknown.
    last_message_ms: i64 = 0,
    /// Negotiated IRCv3 CAP names, space-separated (e.g. "echo-message sasl").
    /// Empty = no caps carried (pre-caps snapshot, or none negotiated). Carried
    /// by name so it survives a build that adds/removes/reorders cap bits.
    caps: []const u8 = "",
    /// Operator grant carried across the UPGRADE so a restored oper keeps its FULL
    /// privilege set — and the derived +a admin umode — not just the `is_oper`
    /// bool. `oper_priv_bits` is `OperPrivileges.toBits()` (append-only ordinals).
    /// 0 bits / empty strings = no grant carried (pre-grant snapshot) → restores
    /// as a bare `is_oper`, exactly the prior behavior.
    oper_priv_bits: u64 = 0,
    oper_class: []const u8 = "",
    oper_title: []const u8 = "",
};

const flag_logged_in: u8 = 1 << 0;
const flag_away_active: u8 = 1 << 1;
const flag_is_oper: u8 = 1 << 2;

/// Encode `snap` into a freshly-allocated buffer the caller owns.
pub fn encode(allocator: std.mem.Allocator, snap: Snapshot) (Error || std.mem.Allocator.Error)![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    inline for (.{ snap.nick, snap.realname, snap.account, snap.real_host, snap.host, snap.away }) |s| {
        if (s.len > std.math.maxInt(u16)) return error.TooLong;
        var len_le: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_le, @intCast(s.len), .little);
        try out.appendSlice(allocator, &len_le);
        try out.appendSlice(allocator, s);
    }
    var flags: u8 = 0;
    if (snap.logged_in) flags |= flag_logged_in;
    if (snap.away_active) flags |= flag_away_active;
    if (snap.is_oper) flags |= flag_is_oper;
    try out.append(allocator, flags);
    var fd_le: [4]u8 = undefined;
    std.mem.writeInt(i32, &fd_le, snap.fd, .little);
    try out.appendSlice(allocator, &fd_le);

    if (snap.channels.len > std.math.maxInt(u16)) return error.TooLong;
    var nch_le: [2]u8 = undefined;
    std.mem.writeInt(u16, &nch_le, @intCast(snap.channels.len), .little);
    try out.appendSlice(allocator, &nch_le);
    for (snap.channels) |ch| {
        if (ch.name.len > std.math.maxInt(u16)) return error.TooLong;
        var len_le: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_le, @intCast(ch.name.len), .little);
        try out.appendSlice(allocator, &len_le);
        try out.appendSlice(allocator, ch.name);
        try out.append(allocator, ch.modes);
    }
    // Trailing signon block (see file header): two monotonic timestamps so the
    // successor can restore WHOIS idle/signon across an in-place UPGRADE.
    var ts_le: [8]u8 = undefined;
    std.mem.writeInt(i64, &ts_le, snap.connected_at_ms, .little);
    try out.appendSlice(allocator, &ts_le);
    std.mem.writeInt(i64, &ts_le, snap.last_message_ms, .little);
    try out.appendSlice(allocator, &ts_le);
    // Trailing CAP block (see file header): the negotiated cap set, by name, so it
    // survives a build that shifts cap bit positions. Sits past the signon block.
    if (snap.caps.len > std.math.maxInt(u16)) return error.TooLong;
    var caps_len_le: [2]u8 = undefined;
    std.mem.writeInt(u16, &caps_len_le, @intCast(snap.caps.len), .little);
    try out.appendSlice(allocator, &caps_len_le);
    try out.appendSlice(allocator, snap.caps);
    // Trailing oper-grant block (see header): privilege bits + class + title so a
    // restored oper keeps its full grant (and the derived +a). Sits past caps.
    var bits_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &bits_le, snap.oper_priv_bits, .little);
    try out.appendSlice(allocator, &bits_le);
    inline for (.{ snap.oper_class, snap.oper_title }) |s| {
        if (s.len > std.math.maxInt(u16)) return error.TooLong;
        var len_le: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_le, @intCast(s.len), .little);
        try out.appendSlice(allocator, &len_le);
        try out.appendSlice(allocator, s);
    }
    // Trailing username block (see header): the client's USER ident, so a migrated
    // session keeps its real ident. Sits past the oper grant; omitting it (pre-
    // username build) decodes to "".
    if (snap.username.len > std.math.maxInt(u16)) return error.TooLong;
    var uname_len_le: [2]u8 = undefined;
    std.mem.writeInt(u16, &uname_len_le, @intCast(snap.username.len), .little);
    try out.appendSlice(allocator, &uname_len_le);
    try out.appendSlice(allocator, snap.username);
    // Trailing secured-flag byte (see header): 1 = the connection had a live TLS
    // engine at seal time. APPEND-ONLY past the username block; a capsule from a
    // pre-flag build omits it and decodes to `was_secured = false`. Growing the
    // payload is why the `.clients` descriptor is at version 2 (capsule.zig).
    try out.append(allocator, @intFromBool(snap.was_secured));
    // Trailing session-token block (see header): `[u8 tlen][tlen bytes]`, the
    // client's multi-session reclaim token. APPEND-ONLY past the secured flag; a
    // pre-token (v2) capsule omits it and the successor mints a fresh token.
    // Growing the payload is why the `.clients` descriptor is at version 3.
    if (snap.session_token.len > std.math.maxInt(u8)) return error.TooLong;
    try out.append(allocator, @intCast(snap.session_token.len));
    try out.appendSlice(allocator, snap.session_token);
    return out.toOwnedSlice(allocator);
}

/// Decode a snapshot, returning views that borrow `bytes`.
pub fn decode(bytes: []const u8) Error!Snapshot {
    var r = Reader{ .buf = bytes };
    const nick = try r.lenPrefixed();
    const realname = try r.lenPrefixed();
    const account = try r.lenPrefixed();
    const real_host = try r.lenPrefixed();
    const host = try r.lenPrefixed();
    const away = try r.lenPrefixed();
    const flags = try r.byte();
    const fd = try r.i32le();
    // The channel list begins here; the iterator self-limits by its leading count,
    // so `channels_blob` stays "the rest" exactly as before — trailing signon
    // bytes (if any) sit past the counted entries and are never iterated.
    const channels_blob = r.buf[r.pos..];
    // Locate the optional trailing signon block by walking past the channel list,
    // then the optional CAP block immediately after it. Both default-empty so a
    // capsule from a build predating either field still decodes cleanly.
    var connected_at_ms: i64 = 0;
    var last_message_ms: i64 = 0;
    var caps: []const u8 = "";
    var oper_priv_bits: u64 = 0;
    var oper_class: []const u8 = "";
    var oper_title: []const u8 = "";
    var username: []const u8 = "";
    var was_secured: bool = false;
    var session_token: []const u8 = &.{};
    // Walk the optional trailing blocks with a running cursor `p`: signon (16) →
    // caps ([u16][bytes]) → oper grant ([u64][u16][class][u16][title]) → username
    // ([u16][bytes]). Each is gated on enough bytes remaining, so a capsule from a
    // build predating any block decodes cleanly with that block (and everything
    // after it) defaulted.
    if (channelRegionEnd(r.buf, r.pos)) |chan_end| {
        var p = chan_end;
        if (r.buf.len - p >= 16) {
            connected_at_ms = std.mem.readInt(i64, r.buf[p..][0..8], .little);
            last_message_ms = std.mem.readInt(i64, r.buf[p + 8 ..][0..8], .little);
            p += 16;
            if (r.buf.len - p >= 2) {
                const n = std.mem.readInt(u16, r.buf[p..][0..2], .little);
                p += 2;
                if (p + n <= r.buf.len) {
                    caps = r.buf[p .. p + n];
                    p += n;
                } else p = r.buf.len; // malformed caps length → stop
            }
            if (r.buf.len - p >= 8) {
                oper_priv_bits = std.mem.readInt(u64, r.buf[p..][0..8], .little);
                p += 8;
                inline for (.{ &oper_class, &oper_title }) |dst| {
                    if (r.buf.len - p >= 2) {
                        const m = std.mem.readInt(u16, r.buf[p..][0..2], .little);
                        p += 2;
                        if (p + m <= r.buf.len) {
                            dst.* = r.buf[p .. p + m];
                            p += m;
                        }
                    }
                }
                // Trailing username block (past the oper grant).
                if (r.buf.len - p >= 2) {
                    const ul = std.mem.readInt(u16, r.buf[p..][0..2], .little);
                    p += 2;
                    if (p + ul <= r.buf.len) {
                        username = r.buf[p .. p + ul];
                        p += ul;
                    }
                }
                // Trailing secured-flag byte (past the username block). Gated on a
                // byte remaining so a pre-flag (v1) capsule defaults it to false.
                if (r.buf.len - p >= 1) {
                    was_secured = r.buf[p] != 0;
                    p += 1;
                    // Trailing session-token block (past the secured flag):
                    // [u8 tlen][tlen bytes]. Gated on bytes remaining so a
                    // pre-token (v2) capsule defaults it to empty — the
                    // successor then mints a fresh token, never drops the client.
                    if (r.buf.len - p >= 1) {
                        const tl: usize = r.buf[p];
                        p += 1;
                        if (r.buf.len - p >= tl) {
                            session_token = r.buf[p .. p + tl];
                            p += tl;
                        }
                    }
                }
            }
        }
    }
    return .{
        .nick = nick,
        .realname = realname,
        .account = account,
        .real_host = real_host,
        .host = host,
        .away = away,
        .logged_in = flags & flag_logged_in != 0,
        .away_active = flags & flag_away_active != 0,
        .is_oper = flags & flag_is_oper != 0,
        .fd = fd,
        .channels_blob = channels_blob,
        .connected_at_ms = connected_at_ms,
        .last_message_ms = last_message_ms,
        .caps = caps,
        .oper_priv_bits = oper_priv_bits,
        .oper_class = oper_class,
        .oper_title = oper_title,
        .username = username,
        .was_secured = was_secured,
        .session_token = session_token,
    };
}

/// Best-effort recovery of the inherited socket fd from a `.clients` snapshot blob
/// whose full `decode` failed (or was force-failed under fault). Unlike the s2s
/// snapshot, the fd is NOT the leading field — it sits past the six length-prefixed
/// identity strings and the flags byte (the last mandatory field before the tolerant
/// trailing tail) — so this walks that fixed prefix and returns the fd, letting the
/// adoption path `close()` the inherited socket instead of leaking it (the fd lives
/// ONLY inside this blob post-execve). Returns null if the blob is truncated before
/// the fd. Mirrors `s2s_snapshot.peekFd` — the same fd-recovery parity seam.
pub fn peekFd(bytes: []const u8) ?i32 {
    var p: usize = 0;
    // Six leading length-prefixed strings: nick, realname, account, real_host,
    // host, away — the fixed mandatory prefix that precedes the fd.
    var i: usize = 0;
    while (i < 6) : (i += 1) {
        if (p + 2 > bytes.len) return null;
        const n = std.mem.readInt(u16, bytes[p..][0..2], .little);
        p += 2;
        if (p + n > bytes.len) return null;
        p += n;
    }
    // Flags byte, then the little-endian i32 fd.
    if (p + 1 > bytes.len) return null;
    p += 1;
    if (p + 4 > bytes.len) return null;
    return std.mem.readInt(i32, bytes[p..][0..4], .little);
}

/// Iterator over a decoded snapshot's `channels_blob` (the trailing channel list).
pub const ChannelIter = struct {
    blob: []const u8,
    pos: usize = 0,
    remaining: ?u16 = null,

    pub fn next(self: *ChannelIter) ?ChannelMembership {
        if (self.remaining == null) {
            if (self.blob.len < 2) {
                self.remaining = 0;
                return null;
            }
            self.remaining = std.mem.readInt(u16, self.blob[0..2], .little);
            self.pos = 2;
        }
        if (self.remaining.? == 0) return null;
        if (self.pos + 2 > self.blob.len) return null;
        const n = std.mem.readInt(u16, self.blob[self.pos..][0..2], .little);
        self.pos += 2;
        if (self.pos + n + 1 > self.blob.len) return null;
        const name = self.blob[self.pos .. self.pos + n];
        self.pos += n;
        const modes = self.blob[self.pos];
        self.pos += 1;
        self.remaining.? -= 1;
        return .{ .name = name, .modes = modes };
    }
};

pub fn channelIter(blob: []const u8) ChannelIter {
    return .{ .blob = blob };
}

/// Return the absolute offset in `buf` one past the channel list that starts at
/// `start` (a u16 count followed by that many `[u16 len][name][u8 modes]` entries),
/// or null if the list is malformed/truncated. Used only to locate the optional
/// trailing signon block; channel iteration itself is unaffected.
fn channelRegionEnd(buf: []const u8, start: usize) ?usize {
    if (buf.len - start < 2) return null;
    const nchan = std.mem.readInt(u16, buf[start..][0..2], .little);
    var p = start + 2;
    var i: u16 = 0;
    while (i < nchan) : (i += 1) {
        if (p + 2 > buf.len) return null;
        const n = std.mem.readInt(u16, buf[p..][0..2], .little);
        p += 2;
        if (p + n + 1 > buf.len) return null;
        p += n + 1;
    }
    return p;
}

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn byte(self: *Reader) Error!u8 {
        if (self.pos + 1 > self.buf.len) return error.Truncated;
        const b = self.buf[self.pos];
        self.pos += 1;
        return b;
    }
    fn i32le(self: *Reader) Error!i32 {
        if (self.pos + 4 > self.buf.len) return error.Truncated;
        const v = std.mem.readInt(i32, self.buf[self.pos..][0..4], .little);
        self.pos += 4;
        return v;
    }
    fn lenPrefixed(self: *Reader) Error![]const u8 {
        if (self.pos + 2 > self.buf.len) return error.Truncated;
        const n = std.mem.readInt(u16, self.buf[self.pos..][0..2], .little);
        self.pos += 2;
        if (self.pos + n > self.buf.len) return error.Truncated;
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "snapshot encode/decode round-trips identity + flags" {
    const allocator = testing.allocator;
    const snap = Snapshot{
        .nick = "alice",
        .realname = "Alice Example",
        .account = "alice",
        .real_host = "10.0.0.5",
        .host = "cloak-ab12.orochi",
        .away = "biab",
        .logged_in = true,
        .away_active = true,
        .is_oper = false,
        .fd = 42,
        .channels = &.{
            .{ .name = "#ops", .modes = 0b101 },
            .{ .name = "#lounge", .modes = 0 },
        },
        .connected_at_ms = 1_700_000_000_123,
        .last_message_ms = 1_700_000_500_456,
        .caps = "echo-message server-time sasl",
        .username = "webchat",
    };
    const bytes = try encode(allocator, snap);
    defer allocator.free(bytes);

    const got = try decode(bytes);
    try testing.expectEqualStrings("webchat", got.username);
    try testing.expectEqual(@as(i32, 42), got.fd);
    try testing.expectEqual(@as(i64, 1_700_000_000_123), got.connected_at_ms);
    try testing.expectEqual(@as(i64, 1_700_000_500_456), got.last_message_ms);
    try testing.expectEqualStrings("echo-message server-time sasl", got.caps);
    var it = channelIter(got.channels_blob);
    const c0 = it.next().?;
    try testing.expectEqualStrings("#ops", c0.name);
    try testing.expectEqual(@as(u8, 0b101), c0.modes);
    const c1 = it.next().?;
    try testing.expectEqualStrings("#lounge", c1.name);
    try testing.expect(it.next() == null);
    try testing.expectEqualStrings("alice", got.nick);
    try testing.expectEqualStrings("Alice Example", got.realname);
    try testing.expectEqualStrings("alice", got.account);
    try testing.expectEqualStrings("10.0.0.5", got.real_host);
    try testing.expectEqualStrings("cloak-ab12.orochi", got.host);
    try testing.expectEqualStrings("biab", got.away);
    try testing.expect(got.logged_in and got.away_active and !got.is_oper);
}

test "empty snapshot round-trips" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{});
    defer allocator.free(bytes);
    const got = try decode(bytes);
    try testing.expectEqual(@as(usize, 0), got.nick.len);
    try testing.expect(!got.logged_in and !got.away_active and !got.is_oper);
    try testing.expectEqual(@as(i64, 0), got.connected_at_ms);
    try testing.expectEqual(@as(i64, 0), got.last_message_ms);
    try testing.expectEqual(@as(usize, 0), got.caps.len);
}

test "caps round-trip and empty caps decode to empty" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{ .nick = "n", .caps = "" });
    defer allocator.free(bytes);
    const got = try decode(bytes);
    try testing.expectEqual(@as(usize, 0), got.caps.len);
}

test "decode tolerates a pre-signon snapshot (no trailing blocks)" {
    const allocator = testing.allocator;
    // Build a snapshot, then truncate the 16-byte signon block + 2-byte caps block
    // to emulate a capsule written by a build that predates both trailing fields.
    const bytes = try encode(allocator, .{
        .nick = "bob",
        .fd = 7,
        .channels = &.{.{ .name = "#a", .modes = 1 }},
        .connected_at_ms = 1234,
        .last_message_ms = 5678,
    });
    defer allocator.free(bytes);
    // Strip every trailing block: signon(16) + empty caps(2) + oper(12) +
    // empty username(2) + secured(1) + empty token(1) = 34 bytes.
    const old = bytes[0 .. bytes.len - 34];

    const got = try decode(old);
    try testing.expectEqualStrings("bob", got.nick);
    try testing.expectEqual(@as(i32, 7), got.fd);
    // Channels still parse; signon defaults to 0 → successor falls back to "now".
    var it = channelIter(got.channels_blob);
    const c0 = it.next().?;
    try testing.expectEqualStrings("#a", c0.name);
    try testing.expect(it.next() == null);
    try testing.expectEqual(@as(i64, 0), got.connected_at_ms);
    try testing.expectEqual(@as(i64, 0), got.last_message_ms);
    try testing.expectEqual(@as(usize, 0), got.caps.len);
}

test "decode tolerates a pre-caps snapshot (signon present, caps absent)" {
    const allocator = testing.allocator;
    // A capsule from the signon-carry build: it has the 16-byte signon block but
    // none of the optional blocks that came after it. Strip every trailing block
    // (caps, oper-grant, username) so the buffer ends right after signon; the
    // decoder must still restore signon and default caps to empty.
    const bytes = try encode(allocator, .{
        .nick = "carol",
        .fd = 9,
        .connected_at_ms = 4321,
        .last_message_ms = 8765,
        .caps = "echo-message",
    });
    defer allocator.free(bytes);
    const caps_block = "echo-message".len + 2; // u16 len + bytes
    const oper_block = 8 + 2 + 2; // priv bits + empty class + empty title
    const username_block = 2; // empty username len prefix
    const secured_block = 1; // trailing was_secured flag byte
    const token_block = 1; // empty session-token len prefix
    const old = bytes[0 .. bytes.len - caps_block - oper_block - username_block - secured_block - token_block];

    const got = try decode(old);
    try testing.expectEqualStrings("carol", got.nick);
    try testing.expectEqual(@as(i64, 4321), got.connected_at_ms);
    try testing.expectEqual(@as(i64, 8765), got.last_message_ms);
    try testing.expectEqual(@as(usize, 0), got.caps.len);
}

test "oper grant round-trips (priv bits + class + title)" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{
        .nick = "kain",
        .account = "kain",
        .logged_in = true,
        .is_oper = true,
        .caps = "sasl",
        .oper_priv_bits = 0x0000_0000_0000_0140, // arbitrary bitmask
        .oper_class = "admin",
        .oper_title = "Server Administrator",
    });
    defer allocator.free(bytes);
    const got = try decode(bytes);
    try testing.expect(got.is_oper);
    try testing.expectEqual(@as(u64, 0x0000_0000_0000_0140), got.oper_priv_bits);
    try testing.expectEqualStrings("admin", got.oper_class);
    try testing.expectEqualStrings("Server Administrator", got.oper_title);
    try testing.expectEqualStrings("sasl", got.caps); // caps still parse before the oper block
}

test "decode tolerates a pre-oper-grant snapshot (caps present, oper block absent)" {
    const allocator = testing.allocator;
    // A capsule from the caps-carry build: signon + caps blocks, but no oper block.
    // Strip the oper block (8 bits + two empty len-prefixed strings = 8+2+2=12).
    const bytes = try encode(allocator, .{ .nick = "dan", .caps = "echo-message", .is_oper = true });
    defer allocator.free(bytes);
    const old = bytes[0 .. bytes.len - 12];
    const got = try decode(old);
    try testing.expectEqualStrings("dan", got.nick);
    try testing.expectEqualStrings("echo-message", got.caps);
    try testing.expect(got.is_oper);
    try testing.expectEqual(@as(u64, 0), got.oper_priv_bits); // defaulted → bare is_oper
    try testing.expectEqual(@as(usize, 0), got.oper_class.len);
}

test "decode rejects a truncated buffer" {
    try testing.expectError(error.Truncated, decode(&[_]u8{ 5, 0, 'a' })); // claims 5, has 1
    try testing.expectError(error.Truncated, decode(&[_]u8{0})); // first length cut off
}

test "session_snapshot was_secured round-trips across an upgrade (true and false)" {
    const allocator = testing.allocator;
    inline for (.{ true, false }) |secured| {
        const bytes = try encode(allocator, .{ .nick = "eve", .fd = 12, .was_secured = secured });
        defer allocator.free(bytes);
        const got = try decode(bytes);
        try testing.expectEqual(secured, got.was_secured);
        try testing.expectEqualStrings("eve", got.nick);
        try testing.expectEqual(@as(i32, 12), got.fd);
    }
}

test "session_snapshot decode tolerates a pre-was_secured capsule (legacy upgrade defaults false)" {
    const allocator = testing.allocator;
    // A capsule from the pre-flag (v1) build: identical bytes minus the single
    // trailing was_secured byte. It MUST decode cleanly with was_secured=false —
    // exactly the historical never-drop behavior — while every other field survives.
    const bytes = try encode(allocator, .{
        .nick = "frank",
        .account = "frank",
        .fd = 33,
        .logged_in = true,
        .is_oper = true,
        .caps = "sasl",
        .oper_priv_bits = 0x0000_0000_0000_00c0,
        .oper_class = "admin",
        .username = "frankusr",
        .was_secured = true,
    });
    defer allocator.free(bytes);
    // Strip the trailing session-token block (1 empty len byte) AND the
    // was_secured byte to emulate the pre-flag (v1) layout.
    const old = bytes[0 .. bytes.len - 2];

    const got = try decode(old);
    try testing.expect(!got.was_secured); // legacy blob → defaults false
    try testing.expectEqualStrings("frank", got.nick);
    try testing.expectEqualStrings("frankusr", got.username);
    try testing.expectEqualStrings("admin", got.oper_class);
    try testing.expectEqual(@as(u64, 0x0000_0000_0000_00c0), got.oper_priv_bits);
    try testing.expect(got.is_oper and got.logged_in);
    try testing.expectEqualStrings("sasl", got.caps);
    try testing.expectEqual(@as(i32, 33), got.fd);
}

test "session-token tail round-trips (present and absent)" {
    const allocator = testing.allocator;
    const tok: [16]u8 = @splat(0x5A);
    const bytes = try encode(allocator, .{
        .nick = "heidi",
        .account = "heidi",
        .logged_in = true,
        .fd = 21,
        .was_secured = true,
        .session_token = &tok,
    });
    defer allocator.free(bytes);
    const got = try decode(bytes);
    try testing.expectEqualSlices(u8, &tok, got.session_token);
    try testing.expect(got.was_secured); // the flag before the token is intact
    try testing.expectEqual(@as(i32, 21), got.fd);

    // No token tracked (not logged in): the block encodes tlen=0 and decodes empty.
    const none = try encode(allocator, .{ .nick = "guest", .fd = 22 });
    defer allocator.free(none);
    try testing.expectEqual(@as(usize, 0), (try decode(none)).session_token.len);
}

test "cross-version: a v2 (pre-token) capsule decodes with an empty token (v2→v3)" {
    const allocator = testing.allocator;
    const tok: [16]u8 = @splat(0x77);
    const bytes = try encode(allocator, .{
        .nick = "ivan",
        .account = "ivan",
        .logged_in = true,
        .fd = 44,
        .was_secured = true,
        .caps = "sasl",
        .username = "ivanusr",
        .session_token = &tok,
    });
    defer allocator.free(bytes);
    // A v2 build's blob is exactly this one minus the trailing token block
    // ([u8 tlen=16][16 bytes]) — strip it to emulate the pre-token layout.
    const v2 = bytes[0 .. bytes.len - 17];

    const got = try decode(v2);
    try testing.expectEqual(@as(usize, 0), got.session_token.len); // defaults empty
    // Every earlier field — including the v2 was_secured flag — still decodes.
    try testing.expect(got.was_secured);
    try testing.expectEqualStrings("ivan", got.nick);
    try testing.expectEqualStrings("ivanusr", got.username);
    try testing.expectEqualStrings("sasl", got.caps);
    try testing.expectEqual(@as(i32, 44), got.fd);
    try testing.expect(got.logged_in);
}

test "session_snapshot peekFd recovers the fd for a decode-failure drop on resume" {
    const allocator = testing.allocator;
    // A valid, fully-populated blob: peekFd must recover the exact fd the successor
    // would need to close on a (fault-forced) decode failure. Walking the fixed
    // mandatory prefix must agree with the fd `decode` itself reports.
    const bytes = try encode(allocator, .{
        .nick = "grace",
        .realname = "Grace Example",
        .account = "grace",
        .real_host = "10.0.0.9",
        .host = "cloak-99.orochi",
        .away = "brb",
        .fd = 57,
        .was_secured = true,
    });
    defer allocator.free(bytes);
    try testing.expectEqual(@as(?i32, 57), peekFd(bytes));
    try testing.expectEqual((try decode(bytes)).fd, peekFd(bytes).?);

    // Too short to even hold the fd → null (nothing to bogus-close).
    try testing.expectEqual(@as(?i32, null), peekFd(&[_]u8{ 1, 2, 3 }));
    // A prefix truncated right before the fd (six empty strings + flags, no fd) → null.
    var no_fd: [13]u8 = @splat(0);
    no_fd[12] = 0; // flags byte present, fd bytes absent
    try testing.expectEqual(@as(?i32, null), peekFd(&no_fd));
}
