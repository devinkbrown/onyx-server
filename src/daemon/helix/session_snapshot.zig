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
//!   [u64 umode_bits][u32 ilen][pending_in][u32 olen][pending_out]  OPTIONAL v4 tail
//!   [u8 was_websocket]    current-schema transport flag (past the v4 tail)
//!   [u8 address_family][4 or 16 address bytes][u8 clone_counted]  current v6 tail
//!   [u8 gagged][u8 ircx][u8 unfurl_opt_in][i64 last_search_ms]
//!   [u8 keytrans_require][i64 nick_claimed_at_ms]  current v6 tail
//!   [u8 flood_present][fixed 539-byte FloodGuard carry if present]  current v6 tail
//!   [u8 mesh_clone_counted][u64 mesh_clone_hash][u8 throttle_counted]  current v7 tail
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
//! `was_secured = false` under the tolerant `decode`, which is exactly the
//! historical (never-drop) behavior. This field was introduced as `.clients`
//! schema v2; the `.clients` descriptor has since advanced to an EXACT current
//! contract (`current_version = min_supported = max_supported = 7`, see
//! helix/capsule.zig), so current adoption uses the strict `decodeCurrent` and a
//! rollback is a cold restart. The tolerant `decode` that reads this byte
//! optionally survives only for explicit legacy/test fixtures.
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
//!
//! The v4 tail (OPTIONAL, written last — past the token block) carries three
//! more pieces so a carried client is byte-for-byte continuous, not just
//! identity-continuous:
//!   * `umode_bits` — the client's user-mode bitset (usermode.UmodeSet.bits,
//!     append-only enum ordinals). Before this, +i/+g/+R and friends silently
//!     reset on every upgrade (an invisible user became visible). Restored
//!     FIRST on the successor, then the server-managed bits (+r/+a/+j) are
//!     re-derived by the normal login/oper paths on top.
//!   * `pending_in` — the partial inbound IRC line accumulated in the RecvQ
//!     (inline `line_buf` or its heap overflow). Dropping it made the next
//!     recv'd bytes parse as a torn/garbage line.
//!   * `pending_out` — the UNSENT SendQ tail (inline + overflow, contiguous)
//!     for a PLAINTEXT connection only. A TLS connection's unsent ciphertext
//!     rides its own `.tls_session` capsule (`pending_out` there), so this
//!     field is empty for secured clients — never both. Dropping it could
//!     tear a reply mid-line when `send_offset` sat inside a line.
//! All three default to 0/empty on a pre-v4 capsule — exactly the historical
//! behavior. Growing the payload is why the `.clients` descriptor is at
//! version 4 (capsule.zig).
//!
//! The current-schema transport flag records whether the inherited client was a
//! WebSocket connection. It is append-only after the complete v4 tail. `decode`
//! remains deliberately tolerant for explicitly-versioned legacy capsules;
//! `decodeCurrent` requires this byte and every preceding current block exactly,
//! so a current capsule can never silently downgrade a WebSocket to raw IRC.
//! Version 5 remains testable through `decode`, but is never negotiated as
//! current state. Version 6 appends the accepted peer's typed IP address and
//! local clone-registration bit. The address family is 0 (absent), 4 (IPv4),
//! or 6 (IPv6); a counted connection must have an address. This lets the
//! successor restore clone-limit occupancy before it serves the carried client.
//! The same exact tail preserves server-controlled GAG, IRCX opt-in, link-preview
//! opt-in, the monotonic SEARCH rate-limit timestamp, and the client's strict
//! key-transparency requirement, and the wall-clock nick-claim grace start.
//! FloodGuard carry stores the exact policy and all metering state. The
//! successor checks its policy against the independently derived connection
//! class and rejects a future monotonic timestamp before adoption. Every
//! boolean is 0/1; all carried integers use explicit little-endian fields.
//! Version 7 appends per-attachment mesh-clone and CloneDetector accounting so
//! closing an adopted connection decrements both restored maps exactly once.
//! An uncounted mesh clone has a zero hash.
const std = @import("std");
const dns = @import("../../proto/dns.zig");
const flood_guard = @import("../flood_guard.zig");

pub const Error = error{
    Truncated,
    TooLong,
    InvalidBoolean,
    InvalidTokenLength,
    InvalidPeerAddress,
    InvalidCountedState,
    InvalidFloodState,
    InvalidMeshCloneState,
    UnknownFlags,
    TrailingData,
};

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
    /// True when this connection used the WebSocket transport at seal time.
    /// The current-schema decoder requires the canonical trailing 0/1 byte so
    /// adoption cannot silently reinterpret a WebSocket as a raw IRC stream.
    was_websocket: bool = false,
    /// Accepted kernel peer or trusted PROXY address. This is a typed IP, not
    /// the client's mutable display host. Absent only when no peer was known.
    peer_addr: ?dns.Address = null,
    /// Whether this physical connection occupied a local clone-limit slot at
    /// seal time. A true value requires `peer_addr` for exact re-registration.
    clone_counted: bool = false,
    /// This attachment contributes one local MeshClones count under its salted
    /// peer-IP hash. When uncounted, the hash must be zero.
    mesh_clone_counted: bool = false,
    mesh_clone_hash: u64 = 0,
    /// This attachment contributes one active CloneDetector count for its IP.
    throttle_counted: bool = false,
    /// Server-controlled IRCX +z GAG and session IRCX opt-in state.
    gagged: bool = false,
    ircx: bool = false,
    /// Link-preview opt-in belongs to this physical client attachment.
    unfurl_opt_in: bool = false,
    /// Monotonic timestamp of this client's last SEARCH, or 0 if none.
    last_search_ms: i64 = 0,
    /// Client demanded strict key-transparency replies. Losing this bit would
    /// silently downgrade missing-log failures into observational responses.
    keytrans_require: bool = false,
    /// Unix-ms grace start for an unauthenticated registered nick, or 0 when
    /// the nick is free or account-owned. This is wall time, not monotonic time.
    nick_claimed_at_ms: i64 = 0,
    /// Exact per-connection rate-limit state. Absence is allowed for a client
    /// whose class has no active guard; server adoption decides that policy.
    flood_guard: ?flood_guard.CarryState = null,
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
    /// Client-settable user-mode bitset (usermode.UmodeSet.bits — append-only
    /// enum ordinals). 0 = pre-v4 capsule (or genuinely no modes); the
    /// successor restores these first, then re-derives server-managed bits.
    umode_bits: u64 = 0,
    /// The partial inbound IRC line pending in the RecvQ at seal time (inline
    /// `line_buf` or its heap overflow). Empty = nothing pending / pre-v4.
    pending_in: []const u8 = &.{},
    /// The unsent SendQ tail (inline + overflow, contiguous) at seal time —
    /// PLAINTEXT connections only (a TLS conn's unsent ciphertext rides its
    /// `.tls_session` capsule instead). Empty = nothing pending / pre-v4.
    pending_out: []const u8 = &.{},
};

const flag_logged_in: u8 = 1 << 0;
const flag_away_active: u8 = 1 << 1;
const flag_is_oper: u8 = 1 << 2;
const known_flags = flag_logged_in | flag_away_active | flag_is_oper;
const known_member_mode_flags: u8 = 0x0f;
const session_token_len: usize = 16;
const current_peer_tail_min_len: usize = 2;
const current_mode_tail_len: usize = 3 + 8 + 1 + 8;
const current_flood_presence_len: usize = 1;
const current_clone_tail_len: usize = 1 + 8 + 1;
/// Enabled byte + policy numerics + four buckets + excess + target ring.
const flood_carry_body_len: usize = 1 + (4 * 3 + 3 + 5) * 8 + (4 * 3 + 3) * 8 + flood_guard.target_slots * 2 * 8 + 2;
comptime {
    if (flood_carry_body_len != 539) @compileError("FloodGuard carry wire length changed");
}

const ModeTail = struct {
    gagged: bool,
    ircx: bool,
    unfurl_opt_in: bool,
    last_search_ms: i64,
    keytrans_require: bool,
    nick_claimed_at_ms: i64,
};

fn readModeTail(r: *Reader) Error!ModeTail {
    return .{
        .gagged = try r.boolean(),
        .ircx = try r.boolean(),
        .unfurl_opt_in = try r.boolean(),
        .last_search_ms = try r.i64le(),
        .keytrans_require = try r.boolean(),
        .nick_claimed_at_ms = try r.i64le(),
    };
}

const PeerTail = struct {
    address: ?dns.Address,
    clone_counted: bool,
};

fn readPeerTail(r: *Reader) Error!PeerTail {
    const family = try r.byte();
    const address: ?dns.Address = switch (family) {
        0 => null,
        4 => .{ .ipv4 = (try r.take(4))[0..4].* },
        6 => .{ .ipv6 = (try r.take(16))[0..16].* },
        else => return error.InvalidPeerAddress,
    };
    const clone_counted = try r.boolean();
    if (clone_counted and address == null) return error.InvalidCountedState;
    return .{ .address = address, .clone_counted = clone_counted };
}

const CloneTail = struct {
    mesh_clone_counted: bool,
    mesh_clone_hash: u64,
    throttle_counted: bool,
};

fn readCloneTail(r: *Reader) Error!CloneTail {
    const mesh_clone_counted = try r.boolean();
    const mesh_clone_hash = try r.u64le();
    const throttle_counted = try r.boolean();
    if (!mesh_clone_counted and mesh_clone_hash != 0) return error.InvalidMeshCloneState;
    return .{
        .mesh_clone_counted = mesh_clone_counted,
        .mesh_clone_hash = mesh_clone_hash,
        .throttle_counted = throttle_counted,
    };
}

fn validateFloodCarry(state: flood_guard.CarryState) Error!void {
    // This is structural validation only. Adoption must import again with the
    // successor's independently derived policy and actual monotonic time.
    _ = flood_guard.FloodGuard.importCarry(state.policy, std.math.maxInt(i64), state) catch
        return error.InvalidFloodState;
}

fn appendFloodU64(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u64) std.mem.Allocator.Error!void {
    var le: [8]u8 = undefined;
    std.mem.writeInt(u64, &le, value, .little);
    try out.appendSlice(allocator, &le);
}

fn appendFloodI64(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: i64) std.mem.Allocator.Error!void {
    var le: [8]u8 = undefined;
    std.mem.writeInt(i64, &le, value, .little);
    try out.appendSlice(allocator, &le);
}

fn appendBucketConfig(out: *std.ArrayList(u8), allocator: std.mem.Allocator, cfg: flood_guard.BucketCfg) std.mem.Allocator.Error!void {
    try appendFloodU64(out, allocator, cfg.capacity);
    try appendFloodU64(out, allocator, cfg.refill_tokens);
    try appendFloodU64(out, allocator, cfg.refill_period_ms);
}

fn readBucketConfig(r: *Reader) Error!flood_guard.BucketCfg {
    return .{
        .capacity = try r.u64le(),
        .refill_tokens = try r.u64le(),
        .refill_period_ms = try r.u64le(),
    };
}

fn appendBucketCarry(out: *std.ArrayList(u8), allocator: std.mem.Allocator, bucket: flood_guard.BucketCarry) std.mem.Allocator.Error!void {
    try appendFloodU64(out, allocator, bucket.tokens);
    try appendFloodI64(out, allocator, bucket.last_ms);
    try appendFloodU64(out, allocator, bucket.carry);
}

fn readBucketCarry(r: *Reader) Error!flood_guard.BucketCarry {
    return .{
        .tokens = try r.u64le(),
        .last_ms = try r.i64le(),
        .carry = try r.u64le(),
    };
}

fn appendFloodCarry(out: *std.ArrayList(u8), allocator: std.mem.Allocator, state: flood_guard.CarryState) std.mem.Allocator.Error!void {
    const start = out.items.len;
    const policy = state.policy;
    try out.append(allocator, @intFromBool(policy.enabled));
    inline for (.{ policy.messages, policy.bytes, policy.commands, policy.target_changes }) |cfg|
        try appendBucketConfig(out, allocator, cfg);
    try appendFloodU64(out, allocator, policy.excess.threshold);
    try appendFloodU64(out, allocator, policy.excess.decay_points);
    try appendFloodU64(out, allocator, policy.excess.decay_period_ms);
    inline for (.{ policy.throttle_penalty, policy.target_change_penalty, policy.privmsg_weight, policy.join_weight, policy.default_weight }) |value|
        try appendFloodU64(out, allocator, value);
    inline for (.{ state.message_rate, state.byte_rate, state.command_rate, state.target_change_rate }) |bucket|
        try appendBucketCarry(out, allocator, bucket);
    try appendFloodU64(out, allocator, state.excess.points);
    try appendFloodI64(out, allocator, state.excess.last_ms);
    try appendFloodU64(out, allocator, state.excess.carry);
    for (state.targets) |key| {
        try appendFloodU64(out, allocator, key.hash);
        try appendFloodU64(out, allocator, key.len);
    }
    try out.append(allocator, state.target_count);
    try out.append(allocator, state.next_target_slot);
    std.debug.assert(out.items.len - start == flood_carry_body_len);
}

fn readFloodCarry(r: *Reader) Error!flood_guard.CarryState {
    const start = r.pos;
    const policy: flood_guard.GuardConfig = .{
        .enabled = try r.boolean(),
        .messages = try readBucketConfig(r),
        .bytes = try readBucketConfig(r),
        .commands = try readBucketConfig(r),
        .target_changes = try readBucketConfig(r),
        .excess = .{
            .threshold = try r.u64le(),
            .decay_points = try r.u64le(),
            .decay_period_ms = try r.u64le(),
        },
        .throttle_penalty = try r.u64le(),
        .target_change_penalty = try r.u64le(),
        .privmsg_weight = try r.u64le(),
        .join_weight = try r.u64le(),
        .default_weight = try r.u64le(),
    };
    var targets: [flood_guard.target_slots]flood_guard.TargetCarry = undefined;
    const message_rate = try readBucketCarry(r);
    const byte_rate = try readBucketCarry(r);
    const command_rate = try readBucketCarry(r);
    const target_change_rate = try readBucketCarry(r);
    const excess: flood_guard.ExcessCarry = .{
        .points = try r.u64le(),
        .last_ms = try r.i64le(),
        .carry = try r.u64le(),
    };
    for (&targets) |*key| {
        key.* = .{ .hash = try r.u64le(), .len = try r.u64le() };
    }
    const state: flood_guard.CarryState = .{
        .policy = policy,
        .message_rate = message_rate,
        .byte_rate = byte_rate,
        .command_rate = command_rate,
        .target_change_rate = target_change_rate,
        .excess = excess,
        .targets = targets,
        .target_count = try r.byte(),
        .next_target_slot = try r.byte(),
    };
    std.debug.assert(r.pos - start == flood_carry_body_len);
    try validateFloodCarry(state);
    return state;
}

/// Encode `snap` into a freshly-allocated buffer the caller owns.
pub fn encode(allocator: std.mem.Allocator, snap: Snapshot) (Error || std.mem.Allocator.Error)![]u8 {
    if (snap.clone_counted and snap.peer_addr == null) return error.InvalidCountedState;
    if (!snap.mesh_clone_counted and snap.mesh_clone_hash != 0) return error.InvalidMeshCloneState;
    if (snap.flood_guard) |state| try validateFloodCarry(state);
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
        if (ch.modes & ~known_member_mode_flags != 0) return error.UnknownFlags;
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
    if (snap.session_token.len != 0 and snap.session_token.len != session_token_len)
        return error.InvalidTokenLength;
    try out.append(allocator, @intCast(snap.session_token.len));
    try out.appendSlice(allocator, snap.session_token);
    // v4 tail (see header): umode bitset + partial inbound line + plaintext
    // unsent SendQ tail. APPEND-ONLY past the token block; a pre-v4 capsule
    // omits it and every field defaults to 0/empty. Growing the payload is why
    // the `.clients` descriptor is at version 4.
    var umode_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &umode_le, snap.umode_bits, .little);
    try out.appendSlice(allocator, &umode_le);
    inline for (.{ snap.pending_in, snap.pending_out }) |pend| {
        if (pend.len > std.math.maxInt(u32)) return error.TooLong;
        var plen_le: [4]u8 = undefined;
        std.mem.writeInt(u32, &plen_le, @intCast(pend.len), .little);
        try out.appendSlice(allocator, &plen_le);
        try out.appendSlice(allocator, pend);
    }
    // Current-schema transport discriminator. This byte is intentionally after
    // the complete v4 tail, making every strict prefix unambiguously incomplete.
    // It is the payload change guarded by the exact `.clients` v5 descriptor.
    try out.append(allocator, @intFromBool(snap.was_websocket));
    // Current v6 peer/count tail. The address is the actual accepted or trusted
    // PROXY IP, not the display host, so the successor can restore the exact
    // clone-limiter registration and release it once on disconnect.
    if (snap.peer_addr) |address| {
        switch (address) {
            .ipv4 => |bytes| {
                try out.append(allocator, 4);
                try out.appendSlice(allocator, &bytes);
            },
            .ipv6 => |bytes| {
                try out.append(allocator, 6);
                try out.appendSlice(allocator, &bytes);
            },
        }
    } else try out.append(allocator, 0);
    try out.append(allocator, @intFromBool(snap.clone_counted));
    try out.append(allocator, @intFromBool(snap.gagged));
    try out.append(allocator, @intFromBool(snap.ircx));
    try out.append(allocator, @intFromBool(snap.unfurl_opt_in));
    var last_search_le: [8]u8 = undefined;
    std.mem.writeInt(i64, &last_search_le, snap.last_search_ms, .little);
    try out.appendSlice(allocator, &last_search_le);
    try out.append(allocator, @intFromBool(snap.keytrans_require));
    var nick_claim_le: [8]u8 = undefined;
    std.mem.writeInt(i64, &nick_claim_le, snap.nick_claimed_at_ms, .little);
    try out.appendSlice(allocator, &nick_claim_le);
    try out.append(allocator, @intFromBool(snap.flood_guard != null));
    if (snap.flood_guard) |state| try appendFloodCarry(&out, allocator, state);
    try out.append(allocator, @intFromBool(snap.mesh_clone_counted));
    try appendFloodU64(&out, allocator, snap.mesh_clone_hash);
    try out.append(allocator, @intFromBool(snap.throttle_counted));
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
    var was_websocket: bool = false;
    var peer_addr: ?dns.Address = null;
    var clone_counted: bool = false;
    var mesh_clone_counted: bool = false;
    var mesh_clone_hash: u64 = 0;
    var throttle_counted: bool = false;
    var gagged: bool = false;
    var ircx: bool = false;
    var unfurl_opt_in: bool = false;
    var last_search_ms: i64 = 0;
    var keytrans_require: bool = false;
    var nick_claimed_at_ms: i64 = 0;
    var flood_carry: ?flood_guard.CarryState = null;
    var session_token: []const u8 = &.{};
    var umode_bits: u64 = 0;
    var pending_in: []const u8 = &.{};
    var pending_out: []const u8 = &.{};
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
                        } else p = r.buf.len; // malformed length → stop (match caps arm)
                    }
                }
                // Trailing username block (past the oper grant).
                if (r.buf.len - p >= 2) {
                    const ul = std.mem.readInt(u16, r.buf[p..][0..2], .little);
                    p += 2;
                    if (p + ul <= r.buf.len) {
                        username = r.buf[p .. p + ul];
                        p += ul;
                    } else p = r.buf.len; // malformed length → stop (match caps arm)
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
                            // v4 tail (past the token block): [u64 umode_bits]
                            // [u32 ilen][pending_in][u32 olen][pending_out].
                            // Gated on bytes remaining so a v3 capsule — which
                            // ends exactly at the token — defaults everything.
                            if (r.buf.len - p >= 8) {
                                umode_bits = std.mem.readInt(u64, r.buf[p..][0..8], .little);
                                p += 8;
                                if (r.buf.len - p >= 4) {
                                    const ilen = std.mem.readInt(u32, r.buf[p..][0..4], .little);
                                    p += 4;
                                    if (r.buf.len - p >= ilen) {
                                        pending_in = r.buf[p .. p + ilen];
                                        p += ilen;
                                        if (r.buf.len - p >= 4) {
                                            const olen = std.mem.readInt(u32, r.buf[p..][0..4], .little);
                                            p += 4;
                                            if (r.buf.len - p >= olen) {
                                                pending_out = r.buf[p .. p + olen];
                                                p += olen;
                                                // Current transport byte. Legacy
                                                // v4 ends exactly before it and
                                                // therefore defaults to false.
                                                if (r.buf.len - p >= 1) {
                                                    was_websocket = r.buf[p] != 0;
                                                    p += 1;
                                                    // Explicit legacy decode may
                                                    // end at the v5 byte. A valid
                                                    // v6 tail is observed when
                                                    // present; a malformed tail
                                                    // defaults without shifting
                                                    // earlier borrowed fields.
                                                    if (r.buf.len - p >= current_peer_tail_min_len) {
                                                        var tail = Reader{ .buf = r.buf[p..] };
                                                        if (readPeerTail(&tail)) |decoded| {
                                                            peer_addr = decoded.address;
                                                            clone_counted = decoded.clone_counted;
                                                            if (tail.buf.len - tail.pos >= current_mode_tail_len) {
                                                                if (readModeTail(&tail)) |mode| {
                                                                    gagged = mode.gagged;
                                                                    ircx = mode.ircx;
                                                                    unfurl_opt_in = mode.unfurl_opt_in;
                                                                    last_search_ms = mode.last_search_ms;
                                                                    keytrans_require = mode.keytrans_require;
                                                                    nick_claimed_at_ms = mode.nick_claimed_at_ms;
                                                                    if (tail.buf.len - tail.pos >= current_flood_presence_len) {
                                                                        if (tail.boolean()) |present| {
                                                                            var flood_valid = !present;
                                                                            if (present) {
                                                                                if (readFloodCarry(&tail)) |state| {
                                                                                    flood_carry = state;
                                                                                    flood_valid = true;
                                                                                } else |_| {}
                                                                            }
                                                                            if (flood_valid and tail.buf.len - tail.pos >= current_clone_tail_len) {
                                                                                if (readCloneTail(&tail)) |clone| {
                                                                                    mesh_clone_counted = clone.mesh_clone_counted;
                                                                                    mesh_clone_hash = clone.mesh_clone_hash;
                                                                                    throttle_counted = clone.throttle_counted;
                                                                                } else |_| {}
                                                                            }
                                                                        } else |_| {}
                                                                    }
                                                                } else |_| {}
                                                            }
                                                        } else |_| {}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
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
        .was_websocket = was_websocket,
        .peer_addr = peer_addr,
        .clone_counted = clone_counted,
        .mesh_clone_counted = mesh_clone_counted,
        .mesh_clone_hash = mesh_clone_hash,
        .throttle_counted = throttle_counted,
        .gagged = gagged,
        .ircx = ircx,
        .unfurl_opt_in = unfurl_opt_in,
        .last_search_ms = last_search_ms,
        .keytrans_require = keytrans_require,
        .nick_claimed_at_ms = nick_claimed_at_ms,
        .flood_guard = flood_carry,
        .session_token = session_token,
        .umode_bits = umode_bits,
        .pending_in = pending_in,
        .pending_out = pending_out,
    };
}

/// Decode exactly the schema emitted by this binary.
///
/// Unlike `decode`, this entry point is intentionally not cross-version
/// tolerant: every block through the v7 clone-accounting tail must be present, every bounded
/// region must end where its declared length says it ends, flag values must be
/// canonical, and no byte may follow the v7 clone-accounting tail. It is
/// allocation-free and returns views borrowing `bytes`.
pub fn decodeCurrent(bytes: []const u8) Error!Snapshot {
    var r = Reader{ .buf = bytes };
    const nick = try r.lenPrefixed();
    const realname = try r.lenPrefixed();
    const account = try r.lenPrefixed();
    const real_host = try r.lenPrefixed();
    const host = try r.lenPrefixed();
    const away = try r.lenPrefixed();

    const flags = try r.byte();
    if (flags & ~known_flags != 0) return error.UnknownFlags;
    const fd = try r.i32le();

    // Preserve only the counted channel region in the strict view. This keeps a
    // malformed count from swallowing a later block and makes channel iteration
    // independent of every current tail field.
    const channels_start = r.pos;
    const nchan = try r.u16le();
    var channel_index: u16 = 0;
    while (channel_index < nchan) : (channel_index += 1) {
        _ = try r.lenPrefixed();
        const modes = try r.byte();
        if (modes & ~known_member_mode_flags != 0) return error.UnknownFlags;
    }
    const channels_blob = bytes[channels_start..r.pos];

    const connected_at_ms = try r.i64le();
    const last_message_ms = try r.i64le();
    const caps = try r.lenPrefixed();
    const oper_priv_bits = try r.u64le();
    const oper_class = try r.lenPrefixed();
    const oper_title = try r.lenPrefixed();
    const username = try r.lenPrefixed();
    const was_secured = try r.boolean();

    const token_length: usize = try r.byte();
    if (token_length != 0 and token_length != session_token_len)
        return error.InvalidTokenLength;
    const session_token = try r.take(token_length);

    const umode_bits = try r.u64le();
    const pending_in = try r.lenPrefixed32();
    const pending_out = try r.lenPrefixed32();
    const was_websocket = try r.boolean();
    const peer = try readPeerTail(&r);
    const mode = try readModeTail(&r);
    const flood_present = try r.boolean();
    const flood_carry = if (flood_present) try readFloodCarry(&r) else null;
    const clone = try readCloneTail(&r);
    if (r.pos != bytes.len) return error.TrailingData;

    return .{
        .nick = nick,
        .realname = realname,
        .account = account,
        .real_host = real_host,
        .host = host,
        .away = away,
        .username = username,
        .logged_in = flags & flag_logged_in != 0,
        .away_active = flags & flag_away_active != 0,
        .is_oper = flags & flag_is_oper != 0,
        .was_secured = was_secured,
        .was_websocket = was_websocket,
        .peer_addr = peer.address,
        .clone_counted = peer.clone_counted,
        .mesh_clone_counted = clone.mesh_clone_counted,
        .mesh_clone_hash = clone.mesh_clone_hash,
        .throttle_counted = clone.throttle_counted,
        .gagged = mode.gagged,
        .ircx = mode.ircx,
        .unfurl_opt_in = mode.unfurl_opt_in,
        .last_search_ms = mode.last_search_ms,
        .keytrans_require = mode.keytrans_require,
        .nick_claimed_at_ms = mode.nick_claimed_at_ms,
        .flood_guard = flood_carry,
        .session_token = session_token,
        .fd = fd,
        .channels_blob = channels_blob,
        .connected_at_ms = connected_at_ms,
        .last_message_ms = last_message_ms,
        .caps = caps,
        .oper_priv_bits = oper_priv_bits,
        .oper_class = oper_class,
        .oper_title = oper_title,
        .umode_bits = umode_bits,
        .pending_in = pending_in,
        .pending_out = pending_out,
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

    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (n > self.buf.len - self.pos) return error.Truncated;
        const out = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return out;
    }

    fn byte(self: *Reader) Error!u8 {
        return (try self.take(1))[0];
    }

    fn boolean(self: *Reader) Error!bool {
        return switch (try self.byte()) {
            0 => false,
            1 => true,
            else => error.InvalidBoolean,
        };
    }

    fn u16le(self: *Reader) Error!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .little);
    }

    fn u32le(self: *Reader) Error!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }

    fn u64le(self: *Reader) Error!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }

    fn i32le(self: *Reader) Error!i32 {
        return std.mem.readInt(i32, (try self.take(4))[0..4], .little);
    }

    fn i64le(self: *Reader) Error!i64 {
        return std.mem.readInt(i64, (try self.take(8))[0..8], .little);
    }

    fn lenPrefixed(self: *Reader) Error![]const u8 {
        return self.take(try self.u16le());
    }

    fn lenPrefixed32(self: *Reader) Error![]const u8 {
        return self.take(try self.u32le());
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
        .host = "cloak-ab12.onyx",
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
    try testing.expectEqualStrings("cloak-ab12.onyx", got.host);
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
    // empty username(2) + secured(1) + empty token(1) + v4 tail(16) + current
    // WebSocket flag(1) + v6 absent-peer/count tail(2) + mode tail(20).
    const old = bytes[0 .. bytes.len - 51 - current_peer_tail_min_len - current_mode_tail_len - current_flood_presence_len - current_clone_tail_len];

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
    const v4_tail = 8 + 4 + 4; // umode bits + two empty pending len prefixes
    const websocket_block = 1; // current transport discriminator
    const old = bytes[0 .. bytes.len - caps_block - oper_block - username_block - secured_block - token_block - v4_tail - websocket_block - current_peer_tail_min_len - current_mode_tail_len - current_flood_presence_len - current_clone_tail_len];

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
    // Strip the oper block onward: 8+2+2 oper + 2 username + 1 secured + 1 token
    // + 16 v4 tail + 1 current WebSocket flag + 2 peer/count + 20 mode bytes (the decoder needs < 8 bytes
    // after caps to default the rest).
    const bytes = try encode(allocator, .{ .nick = "dan", .caps = "echo-message", .is_oper = true });
    defer allocator.free(bytes);
    const old = bytes[0 .. bytes.len - 33 - current_peer_tail_min_len - current_mode_tail_len - current_flood_presence_len - current_clone_tail_len];
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

test "tolerant decode stops the tail walk on an over-long oper-grant length" {
    // L6: the oper_class/oper_title/username arms must STOP the tail walk on an
    // over-long length (like the caps arm), never leave the cursor misaligned and
    // keep reading the following blocks from shifted bytes. Encode a full tail,
    // then corrupt the oper_class length prefix to overrun the buffer.
    const allocator = testing.allocator;
    const token16 = "0123456789abcdef";
    const bytes = try encode(allocator, .{
        .nick = "kain",
        .is_oper = true,
        .caps = "sasl",
        .oper_priv_bits = 0x140,
        .oper_class = "UNIQ_OPER_CLASS_MARKER",
        .oper_title = "UNIQ_OPER_TITLE_MARKER",
        .username = "kainuser",
        .was_secured = true,
        .session_token = token16,
    });
    defer allocator.free(bytes);

    const corrupt = try allocator.dupe(u8, bytes);
    defer allocator.free(corrupt);
    // The 2-byte little-endian oper_class length sits immediately before the
    // oper_class string; overrun it far past the buffer end.
    const class_at = std.mem.indexOf(u8, corrupt, "UNIQ_OPER_CLASS_MARKER").?;
    std.mem.writeInt(u16, corrupt[class_at - 2 ..][0..2], 0xFFFF, .little);

    const got = try decode(corrupt);
    // The walk stops at the malformed length: oper_class and every FOLLOWING
    // optional block default cleanly rather than reading misaligned bytes.
    try testing.expectEqual(@as(usize, 0), got.oper_class.len);
    try testing.expectEqual(@as(usize, 0), got.oper_title.len);
    try testing.expectEqual(@as(usize, 0), got.username.len);
    try testing.expect(!got.was_secured); // NOT read from a shifted cursor
    try testing.expectEqual(@as(usize, 0), got.session_token.len);
    // The blocks BEFORE the corruption still parse.
    try testing.expectEqualStrings("kain", got.nick);
    try testing.expectEqualStrings("sasl", got.caps);
    try testing.expectEqual(@as(u64, 0x140), got.oper_priv_bits);
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
    // Strip the current WebSocket byte (1), v4 tail (16), trailing session-token
    // block (1 empty len byte), and was_secured byte to emulate pre-flag v1.
    const old = bytes[0 .. bytes.len - 19 - current_peer_tail_min_len - current_mode_tail_len - current_flood_presence_len - current_clone_tail_len];

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
    // A v2 build's blob is exactly this one minus the current WebSocket byte,
    // v4 tail (16), and trailing token block ([u8 tlen=16][16 bytes]).
    const v2 = bytes[0 .. bytes.len - 34 - current_peer_tail_min_len - current_mode_tail_len - current_flood_presence_len - current_clone_tail_len];

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
        .host = "cloak-99.onyx",
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

test "v4 tail round-trips (umodes + pending_in + pending_out)" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{
        .nick = "judy",
        .account = "judy",
        .logged_in = true,
        .fd = 61,
        .caps = "sasl",
        .umode_bits = 0b1010_0101,
        .pending_in = "PRIVMSG #root :half a li",
        .pending_out = ":srv 001 judy :Welco",
    });
    defer allocator.free(bytes);
    const got = try decode(bytes);
    try testing.expectEqual(@as(u64, 0b1010_0101), got.umode_bits);
    try testing.expectEqualStrings("PRIVMSG #root :half a li", got.pending_in);
    try testing.expectEqualStrings(":srv 001 judy :Welco", got.pending_out);
    // Everything before the v4 tail still decodes.
    try testing.expectEqualStrings("judy", got.nick);
    try testing.expectEqualStrings("sasl", got.caps);
    try testing.expectEqual(@as(i32, 61), got.fd);
}

test "cross-version: a v3 (pre-v4-tail) capsule decodes with defaults (v3->v4)" {
    const allocator = testing.allocator;
    const tok: [16]u8 = @splat(0x11);
    const bytes = try encode(allocator, .{
        .nick = "kilo",
        .account = "kilo",
        .logged_in = true,
        .fd = 71,
        .was_secured = true,
        .session_token = &tok,
        .umode_bits = 0xff,
        .pending_in = "torn",
        .pending_out = "tear",
    });
    defer allocator.free(bytes);
    // A v3 build's blob is this one minus the v4 tail and current WebSocket byte:
    // [u64 umode][u32 ilen=4]["torn"][u32 olen=4]["tear"] + bool = 24+1.
    const v3 = bytes[0 .. bytes.len - 25 - current_peer_tail_min_len - current_mode_tail_len - current_flood_presence_len - current_clone_tail_len];

    const got = try decode(v3);
    try testing.expectEqual(@as(u64, 0), got.umode_bits); // defaults
    try testing.expectEqual(@as(usize, 0), got.pending_in.len);
    try testing.expectEqual(@as(usize, 0), got.pending_out.len);
    // Every earlier field — including the v3 token tail — still decodes.
    try testing.expectEqualSlices(u8, &tok, got.session_token);
    try testing.expect(got.was_secured);
    try testing.expectEqualStrings("kilo", got.nick);
    try testing.expectEqual(@as(i32, 71), got.fd);
    try testing.expect(got.logged_in);
}

test "decodeCurrent round-trips every current block including WebSocket transport" {
    const allocator = testing.allocator;
    const token: [session_token_len]u8 = @splat(0xC5);
    const bytes = try encode(allocator, .{
        .nick = "lotus",
        .realname = "Lotus Current",
        .account = "lotus",
        .real_host = "192.0.2.4",
        .host = "cloak-current.onyx",
        .away = "migrating",
        .username = "ocean",
        .logged_in = true,
        .away_active = true,
        .is_oper = true,
        .was_secured = true,
        .was_websocket = true,
        .peer_addr = .{ .ipv4 = .{ 192, 0, 2, 4 } },
        .clone_counted = true,
        .mesh_clone_counted = true,
        .mesh_clone_hash = 0xA5A6_A7A8_A9AA_ABAC,
        .throttle_counted = true,
        .gagged = true,
        .ircx = true,
        .unfurl_opt_in = true,
        .last_search_ms = 123_321,
        .keytrans_require = true,
        .nick_claimed_at_ms = 1_700_000_123_456,
        .session_token = &token,
        .fd = 91,
        .channels = &.{
            .{ .name = "#mesh", .modes = known_member_mode_flags },
            .{ .name = "#roadmap", .modes = 0 },
        },
        .connected_at_ms = 123_456,
        .last_message_ms = 123_999,
        .caps = "message-tags server-time",
        .oper_priv_bits = 0xA5,
        .oper_class = "admin",
        .oper_title = "Mesh Operator",
        .umode_bits = 0x55,
        .pending_in = "PRIVMSG #mesh :partial",
        .pending_out = ":onyx NOTICE lotus :queued\r\n",
    });
    defer allocator.free(bytes);

    const got = try decodeCurrent(bytes);
    try testing.expectEqualStrings("lotus", got.nick);
    try testing.expectEqualStrings("Lotus Current", got.realname);
    try testing.expectEqualStrings("lotus", got.account);
    try testing.expectEqualStrings("192.0.2.4", got.real_host);
    try testing.expectEqualStrings("cloak-current.onyx", got.host);
    try testing.expectEqualStrings("migrating", got.away);
    try testing.expectEqualStrings("ocean", got.username);
    try testing.expect(got.logged_in and got.away_active and got.is_oper);
    try testing.expect(got.was_secured and got.was_websocket);
    try testing.expectEqualDeep(@as(?dns.Address, .{ .ipv4 = .{ 192, 0, 2, 4 } }), got.peer_addr);
    try testing.expect(got.clone_counted);
    try testing.expect(got.mesh_clone_counted and got.throttle_counted);
    try testing.expectEqual(@as(u64, 0xA5A6_A7A8_A9AA_ABAC), got.mesh_clone_hash);
    try testing.expect(got.gagged and got.ircx and got.unfurl_opt_in);
    try testing.expectEqual(@as(i64, 123_321), got.last_search_ms);
    try testing.expect(got.keytrans_require);
    try testing.expectEqual(@as(i64, 1_700_000_123_456), got.nick_claimed_at_ms);
    try testing.expectEqualSlices(u8, &token, got.session_token);
    try testing.expectEqual(@as(i32, 91), got.fd);
    try testing.expectEqual(@as(i64, 123_456), got.connected_at_ms);
    try testing.expectEqual(@as(i64, 123_999), got.last_message_ms);
    try testing.expectEqualStrings("message-tags server-time", got.caps);
    try testing.expectEqual(@as(u64, 0xA5), got.oper_priv_bits);
    try testing.expectEqualStrings("admin", got.oper_class);
    try testing.expectEqualStrings("Mesh Operator", got.oper_title);
    try testing.expectEqual(@as(u64, 0x55), got.umode_bits);
    try testing.expectEqualStrings("PRIVMSG #mesh :partial", got.pending_in);
    try testing.expectEqualStrings(":onyx NOTICE lotus :queued\r\n", got.pending_out);

    var channels = channelIter(got.channels_blob);
    const first = channels.next().?;
    try testing.expectEqualStrings("#mesh", first.name);
    try testing.expectEqual(known_member_mode_flags, first.modes);
    try testing.expectEqualStrings("#roadmap", channels.next().?.name);
    try testing.expect(channels.next() == null);
    // The tolerant legacy decoder also observes the append-only current byte.
    try testing.expect((try decode(bytes)).was_websocket);
    try testing.expectEqualDeep(got.peer_addr, (try decode(bytes)).peer_addr);
    try testing.expect((try decode(bytes)).gagged);
}

test "current peer tail round-trips IPv6 and legacy v5 defaults" {
    const allocator = testing.allocator;
    const ipv6: dns.Address = .{ .ipv6 = .{ 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 } };
    const bytes = try encode(allocator, .{ .fd = 54, .peer_addr = ipv6, .clone_counted = true });
    defer allocator.free(bytes);
    const current = try decodeCurrent(bytes);
    try testing.expectEqualDeep(@as(?dns.Address, ipv6), current.peer_addr);
    try testing.expect(current.clone_counted);
    const tolerant = try decode(bytes);
    try testing.expectEqualDeep(@as(?dns.Address, ipv6), tolerant.peer_addr);
    try testing.expect(tolerant.clone_counted);

    // The explicit legacy decoder recognizes an exact v5 body without the
    // peer/count tail, but the current decoder refuses the incomplete layout.
    const v5 = bytes[0 .. bytes.len - (1 + 16 + 1) - current_mode_tail_len - current_flood_presence_len - current_clone_tail_len];
    const old = try decode(v5);
    try testing.expect(old.peer_addr == null);
    try testing.expect(!old.clone_counted);
    try testing.expect(!old.gagged and !old.ircx and !old.unfurl_opt_in);
    try testing.expectEqual(@as(i64, 0), old.last_search_ms);
    try testing.expect(!old.keytrans_require);
    try testing.expectEqual(@as(i64, 0), old.nick_claimed_at_ms);
    try testing.expectError(error.Truncated, decodeCurrent(v5));
}

test "current peer tail rejects invalid address and clone accounting" {
    const allocator = testing.allocator;
    try testing.expectError(error.InvalidCountedState, encode(allocator, .{ .clone_counted = true }));
    const empty = try encode(allocator, .{});
    defer allocator.free(empty);
    try testing.expectEqual(@as(usize, 103), empty.len);
    // The exact empty layout ends with [websocket=0][family=0][counted=0].
    empty[70] = 5;
    try testing.expectError(error.InvalidPeerAddress, decodeCurrent(empty));
    empty[70] = 0;
    empty[71] = 1;
    try testing.expectError(error.InvalidCountedState, decodeCurrent(empty));
    empty[71] = 2;
    try testing.expectError(error.InvalidBoolean, decodeCurrent(empty));
    empty[71] = 0;
    empty[70] = 4;
    try testing.expectError(error.Truncated, decodeCurrent(empty));
    empty[70] = 6;
    try testing.expectError(error.Truncated, decodeCurrent(empty));

    const ipv4 = try encode(allocator, .{ .peer_addr = .{ .ipv4 = .{ 203, 0, 113, 9 } } });
    defer allocator.free(ipv4);
    try testing.expectError(error.Truncated, decodeCurrent(ipv4[0 .. ipv4.len - 1]));
    const extra = try allocator.alloc(u8, ipv4.len + 1);
    defer allocator.free(extra);
    @memcpy(extra[0..ipv4.len], ipv4);
    extra[ipv4.len] = 0;
    try testing.expectError(error.TrailingData, decodeCurrent(extra));
}

test "current client mode tail is exact and uses canonical booleans" {
    const allocator = testing.allocator;
    const wire = try encode(allocator, .{
        .gagged = true,
        .ircx = true,
        .unfurl_opt_in = true,
        .last_search_ms = 0x0102_0304_0506_0708,
        .keytrans_require = true,
        .nick_claimed_at_ms = 0x1112_1314_1516_1718,
    });
    defer allocator.free(wire);
    try testing.expectEqual(@as(usize, 103), wire.len);
    try testing.expectEqualSlices(u8, &.{ 8, 7, 6, 5, 4, 3, 2, 1 }, wire[75..83]);
    try testing.expectEqual(@as(u8, 1), wire[83]);
    try testing.expectEqualSlices(u8, &.{ 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11 }, wire[84..92]);
    const got = try decodeCurrent(wire);
    try testing.expect(got.gagged and got.ircx and got.unfurl_opt_in);
    try testing.expectEqual(@as(i64, 0x0102_0304_0506_0708), got.last_search_ms);
    try testing.expect(got.keytrans_require);
    try testing.expectEqual(@as(i64, 0x1112_1314_1516_1718), got.nick_claimed_at_ms);
    try testing.expectEqual(@as(u8, 0), wire[92]);

    const altered = try allocator.dupe(u8, wire);
    defer allocator.free(altered);
    inline for (.{ 72, 73, 74 }) |offset| {
        altered[offset] = 2;
        try testing.expectError(error.InvalidBoolean, decodeCurrent(altered));
        altered[offset] = 1;
    }
    altered[83] = 2;
    try testing.expectError(error.InvalidBoolean, decodeCurrent(altered));
    altered[83] = 1;
    altered[92] = 2;
    try testing.expectError(error.InvalidBoolean, decodeCurrent(altered));
    try testing.expectError(error.Truncated, decodeCurrent(wire[0 .. wire.len - 1]));
}

fn testFloodCarry() !flood_guard.CarryState {
    const cfg: flood_guard.GuardConfig = .{
        .enabled = true,
        .messages = .{ .capacity = 4, .refill_tokens = 1, .refill_period_ms = 1000 },
        .bytes = .{ .capacity = 256, .refill_tokens = 5, .refill_period_ms = 1000 },
        .commands = .{ .capacity = 1, .refill_tokens = 1, .refill_period_ms = 1000 },
        .target_changes = .{ .capacity = 4, .refill_tokens = 1, .refill_period_ms = 1000 },
        .excess = .{ .threshold = 10, .decay_points = 1, .decay_period_ms = 1000 },
        .throttle_penalty = 2,
        .target_change_penalty = 3,
        .privmsg_weight = 1,
        .join_weight = 2,
        .default_weight = 1,
    };
    var guard = flood_guard.FloodGuard.init(cfg, 100);
    try testing.expectEqual(flood_guard.Decision.allow, guard.classifyRaw(100, "PRIVMSG #alpha :hi\r\n"));
    try testing.expectEqual(flood_guard.Decision.throttle, guard.classifyRaw(100, "WHOIS a\r\n"));
    guard.decay(175);
    return guard.exportCarry();
}

test "current FloodGuard carry has exact fixed-size typed round-trip" {
    const allocator = testing.allocator;
    const state = try testFloodCarry();
    const wire = try encode(allocator, .{ .flood_guard = state });
    defer allocator.free(wire);
    try testing.expectEqual(@as(usize, 103 + flood_carry_body_len), wire.len);
    try testing.expectEqual(@as(u8, 1), wire[92]);
    try testing.expectEqual(@as(u8, 1), wire[93]); // policy.enabled
    const current = try decodeCurrent(wire);
    try testing.expectEqualDeep(state, current.flood_guard.?);
    try testing.expectEqualDeep(state, (try decode(wire)).flood_guard.?);
    // The typed image remains directly importable at its original policy.
    _ = try flood_guard.FloodGuard.importCarry(state.policy, 175, current.flood_guard.?);
}

test "current FloodGuard carry rejects truncated, noncanonical, and invalid state" {
    const allocator = testing.allocator;
    const state = try testFloodCarry();
    const wire = try encode(allocator, .{ .flood_guard = state });
    defer allocator.free(wire);
    const altered = try allocator.dupe(u8, wire);
    defer allocator.free(altered);

    // The marker alone never means a valid present image.
    try testing.expectError(error.Truncated, decodeCurrent(wire[0..93]));
    try testing.expectError(error.Truncated, decodeCurrent(wire[0 .. wire.len - 1]));
    altered[93] = 2;
    try testing.expectError(error.InvalidBoolean, decodeCurrent(altered));
    altered[93] = 1;

    // Four bucket images start after the 161-byte policy. A balance above its
    // configured capacity cannot be accepted as freshly minted credit.
    std.mem.writeInt(u64, altered[254..262], std.math.maxInt(u64), .little);
    try testing.expectError(error.InvalidFloodState, decodeCurrent(altered));
    @memcpy(altered, wire);
    // The first target's length must be nonzero, and ring counts are bounded.
    std.mem.writeInt(u64, altered[382..390], 0, .little);
    try testing.expectError(error.InvalidFloodState, decodeCurrent(altered));
    @memcpy(altered, wire);
    altered[wire.len - current_clone_tail_len - 2] = flood_guard.target_slots + 1;
    try testing.expectError(error.InvalidFloodState, decodeCurrent(altered));
    @memcpy(altered, wire);
    // A malformed source image must fail before the encoder allocates a blob.
    var malformed = state;
    malformed.command_rate.carry = state.policy.commands.refill_period_ms;
    try testing.expectError(error.InvalidFloodState, encode(allocator, .{ .flood_guard = malformed }));
}

test "v7 clone accounting tail round-trips and older bodies default uncounted" {
    const allocator = testing.allocator;
    const hash: u64 = 0x0102_0304_0506_0708;
    const wire = try encode(allocator, .{
        .peer_addr = .{ .ipv4 = .{ 192, 0, 2, 17 } },
        .mesh_clone_counted = true,
        .mesh_clone_hash = hash,
        .throttle_counted = true,
    });
    defer allocator.free(wire);
    const tail = wire.len - current_clone_tail_len;
    try testing.expectEqual(@as(u8, 1), wire[tail]);
    try testing.expectEqualSlices(u8, &.{ 8, 7, 6, 5, 4, 3, 2, 1 }, wire[tail + 1 .. tail + 9]);
    try testing.expectEqual(@as(u8, 1), wire[tail + 9]);
    const current = try decodeCurrent(wire);
    try testing.expect(current.mesh_clone_counted and current.throttle_counted);
    try testing.expectEqual(hash, current.mesh_clone_hash);
    const tolerant = try decode(wire);
    try testing.expect(tolerant.mesh_clone_counted and tolerant.throttle_counted);
    try testing.expectEqual(hash, tolerant.mesh_clone_hash);

    const old_v6 = wire[0..tail];
    const legacy = try decode(old_v6);
    try testing.expect(!legacy.mesh_clone_counted and !legacy.throttle_counted);
    try testing.expectEqual(@as(u64, 0), legacy.mesh_clone_hash);
    try testing.expectError(error.Truncated, decodeCurrent(old_v6));
}

test "v7 clone accounting tail rejects malformed booleans and uncounted hash" {
    const allocator = testing.allocator;
    try testing.expectError(error.InvalidMeshCloneState, encode(allocator, .{ .mesh_clone_hash = 1 }));
    const wire = try encode(allocator, .{});
    defer allocator.free(wire);
    const tail = wire.len - current_clone_tail_len;
    const altered = try allocator.dupe(u8, wire);
    defer allocator.free(altered);

    altered[tail] = 2;
    try testing.expectError(error.InvalidBoolean, decodeCurrent(altered));
    altered[tail] = 0;
    altered[tail + 1] = 1;
    try testing.expectError(error.InvalidMeshCloneState, decodeCurrent(altered));
    altered[tail + 1] = 0;
    altered[tail + 9] = 2;
    try testing.expectError(error.InvalidBoolean, decodeCurrent(altered));
    try testing.expectError(error.Truncated, decodeCurrent(wire[0 .. wire.len - 1]));
}

test "current snapshot encoding is leak-free across every allocation failure" {
    const token: [session_token_len]u8 = @splat(0xD4);
    const channels = [_]ChannelMembership{
        .{ .name = "#mesh", .modes = known_member_mode_flags },
        .{ .name = "#roadmap", .modes = 0 },
    };
    const snap = Snapshot{
        .nick = "lotus",
        .realname = "Lotus OOM Sweep",
        .account = "lotus",
        .real_host = "192.0.2.9",
        .host = "cloak-oom.onyx",
        .away = "migrating",
        .username = "ocean",
        .logged_in = true,
        .away_active = true,
        .is_oper = true,
        .was_secured = true,
        .was_websocket = true,
        .peer_addr = .{ .ipv6 = .{ 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10 } },
        .clone_counted = true,
        .mesh_clone_counted = true,
        .mesh_clone_hash = 0x0102_0304_0506_0708,
        .throttle_counted = true,
        .gagged = true,
        .ircx = true,
        .unfurl_opt_in = true,
        .last_search_ms = 321_555,
        .keytrans_require = true,
        .nick_claimed_at_ms = 1_700_001_234_567,
        .session_token = &token,
        .fd = 92,
        .channels = &channels,
        .connected_at_ms = 321_000,
        .last_message_ms = 321_999,
        .caps = "message-tags server-time batch",
        .oper_priv_bits = 0x5A,
        .oper_class = "admin",
        .oper_title = "Mesh Operator",
        .umode_bits = 0xAA,
        .pending_in = "PRIVMSG #mesh :partial",
        .pending_out = ":onyx NOTICE lotus :queued\r\n",
    };

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, snapshot: Snapshot) !void {
            const bytes = try encode(allocator, snapshot);
            defer allocator.free(bytes);
            const restored = try decodeCurrent(bytes);
            try testing.expectEqualStrings(snapshot.nick, restored.nick);
            try testing.expectEqualSlices(u8, snapshot.session_token, restored.session_token);
            try testing.expectEqualStrings(snapshot.pending_out, restored.pending_out);
            try testing.expect(restored.was_websocket);
            try testing.expectEqualDeep(snapshot.peer_addr, restored.peer_addr);
            try testing.expect(restored.clone_counted);
            try testing.expect(restored.mesh_clone_counted and restored.throttle_counted);
            try testing.expectEqual(snapshot.mesh_clone_hash, restored.mesh_clone_hash);
            try testing.expect(restored.gagged and restored.ircx and restored.unfurl_opt_in);
            try testing.expectEqual(snapshot.last_search_ms, restored.last_search_ms);
            try testing.expect(restored.keytrans_require);
            try testing.expectEqual(snapshot.nick_claimed_at_ms, restored.nick_claimed_at_ms);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{snap});
}

test "decodeCurrent rejects every proper prefix and every trailing byte" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{});
    defer allocator.free(bytes);

    // Empty current snapshot has a deliberately stable structural minimum:
    // every proper prefix, including a complete v4 blob without was_websocket,
    // is incomplete for the current decoder.
    try testing.expectEqual(@as(usize, 103), bytes.len);
    for (0..bytes.len) |end| {
        try testing.expectError(error.Truncated, decodeCurrent(bytes[0..end]));
    }
    _ = try decodeCurrent(bytes);

    var with_trailing: [104]u8 = undefined;
    @memcpy(with_trailing[0..bytes.len], bytes);
    with_trailing[bytes.len] = 0;
    try testing.expectError(error.TrailingData, decodeCurrent(&with_trailing));
}

test "decodeCurrent rejects noncanonical booleans and unknown flag bits" {
    const allocator = testing.allocator;
    const empty = try encode(allocator, .{});
    defer allocator.free(empty);
    try testing.expectEqual(@as(usize, 103), empty.len);

    // Six empty u16 strings precede the primary flag byte.
    empty[12] = 0x08;
    try testing.expectError(error.UnknownFlags, decodeCurrent(empty));
    empty[12] = 0;

    // Empty-current exact offsets: secured=51, websocket=69.
    empty[51] = 2;
    try testing.expectError(error.InvalidBoolean, decodeCurrent(empty));
    empty[51] = 0;
    empty[69] = 0xff;
    try testing.expectError(error.InvalidBoolean, decodeCurrent(empty));

    const channel_bytes = try encode(allocator, .{ .channels = &.{.{ .name = "#c", .modes = 0 }} });
    defer allocator.free(channel_bytes);
    // count starts at 17; [u16 name-len]["#c"] puts member flags at 23.
    channel_bytes[23] = 0x10;
    try testing.expectError(error.UnknownFlags, decodeCurrent(channel_bytes));

    try testing.expectError(
        error.UnknownFlags,
        encode(allocator, .{ .channels = &.{.{ .name = "#c", .modes = 0x80 }} }),
    );
}

test "decodeCurrent enforces exact channel token and pending length regions" {
    const allocator = testing.allocator;
    const pristine = try encode(allocator, .{});
    defer allocator.free(pristine);
    var malformed = try allocator.dupe(u8, pristine);
    defer allocator.free(malformed);

    // Claimed identity bytes cannot overlap the mandatory grammar.
    std.mem.writeInt(u16, malformed[0..2], std.math.maxInt(u16), .little);
    try testing.expectError(error.Truncated, decodeCurrent(malformed));
    @memcpy(malformed, pristine);

    // A fabricated channel entry shifts the exact tail boundary and is rejected.
    std.mem.writeInt(u16, malformed[17..19], 1, .little);
    try testing.expectError(error.Truncated, decodeCurrent(malformed));
    @memcpy(malformed, pristine);

    // Empty-current exact offsets: caps len=35, token len=52, inbound len=61,
    // outbound len=65. Oversized declarations must never be clamped/tolerated.
    std.mem.writeInt(u16, malformed[35..37], std.math.maxInt(u16), .little);
    try testing.expectError(error.Truncated, decodeCurrent(malformed));
    @memcpy(malformed, pristine);

    inline for (.{ 1, 15, 17, 255 }) |bad_token_len| {
        malformed[52] = bad_token_len;
        try testing.expectError(error.InvalidTokenLength, decodeCurrent(malformed));
        malformed[52] = 0;
    }
    // A canonical 16-byte declaration is still truncated unless all 16 bytes
    // and the blocks after them actually exist at their shifted positions.
    malformed[52] = session_token_len;
    try testing.expectError(error.Truncated, decodeCurrent(malformed));
    @memcpy(malformed, pristine);

    std.mem.writeInt(u32, malformed[61..65], std.math.maxInt(u32), .little);
    try testing.expectError(error.Truncated, decodeCurrent(malformed));
    @memcpy(malformed, pristine);
    std.mem.writeInt(u32, malformed[65..69], std.math.maxInt(u32), .little);
    try testing.expectError(error.Truncated, decodeCurrent(malformed));

    try testing.expectError(error.InvalidTokenLength, encode(allocator, .{ .session_token = "short" }));
}

test "decodeCurrent is statically allocation-free and cannot return OutOfMemory" {
    const fn_info = @typeInfo(@TypeOf(decodeCurrent)).@"fn";
    comptime {
        if (fn_info.param_types.len != 1) @compileError("decodeCurrent must accept only borrowed bytes");
        const return_type = fn_info.return_type orelse @compileError("decodeCurrent must return a value");
        const decode_errors = @typeInfo(return_type).error_union.error_set;
        const names = @typeInfo(decode_errors).error_set.error_names orelse
            @compileError("decodeCurrent must retain a concrete error set");
        for (names) |name| {
            if (std.mem.eql(u8, name, "OutOfMemory"))
                @compileError("decodeCurrent must remain allocation-free");
        }
    }

    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{ .was_websocket = true });
    defer allocator.free(bytes);
    try testing.expect((try decodeCurrent(bytes)).was_websocket);
}
