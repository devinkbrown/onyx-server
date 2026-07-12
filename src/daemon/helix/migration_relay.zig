// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! migration_relay — S2S session-migration relay API for the Helix subsystem.
//!
//! Cross-machine session migration moves a logged-in client's session from one
//! node (the *origin*) to another (the *target*) so a reconnecting client lands
//! on the target with its nick, umodes, channels, and account already restored.
//!
//! This module is the *pure*, socket-free relay surface the server loop calls:
//! the server hands us frame bytes in and out; we never touch a socket, a clock,
//! or the filesystem. It ties the migration capsule + snapshot + signed token +
//! journal + policy + metrics together into one cohesive API:
//!
//!   * `MigrationOrigin.prepare(account, snapshot)` mints a signed token, records
//!     the pending migration in the journal/policy, and returns the wire frame
//!     bytes (plus the token, so the origin can correlate the reply).
//!   * `MigrationTarget.accept(frame_bytes)` decodes the frame, verifies the
//!     token signature against the pinned origin key, enforces replay/duplicate
//!     policy via its journal, records metrics, and yields the decoded `Capsule`
//!     whose snapshot the server restores.
//!   * `MigrationTarget.reclaimToken(account)` returns the token a reconnecting
//!     client must present to prove it owns the just-migrated session. The match
//!     is constant-time so a guessing client learns nothing from timing.
//!
//! Crypto is NOT reinvented here. Token signing/verification composes the
//! canonical `signed_object` layer (Ed25519 over signature-stable CoilPack
//! bytes); capsule/snapshot serialization composes the `coilpack_value` layer;
//! constant-time comparison composes `secure_fns.ctEq`.
//!
//! Determinism: every key in this module is sourced from caller-supplied bytes
//! (account name, deterministic nonce) or a deterministically-generated Ed25519
//! key. Nothing here reads `std.crypto.random` or the OS CSPRNG.
//!
//! Target: 64-bit only (x86_64 / aarch64).

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

const cpv = @import("../../proto/coilpack_value.zig");
const signed_object = @import("../../proto/signed_object.zig");
const secure_fns = @import("../../proto/secure_fns.zig");

comptime {
    // Hard 64-bit-only guarantee, matching the rest of the daemon.
    if (@bitSizeOf(usize) != 64) {
        @compileError("migration_relay targets 64-bit only");
    }
}

// ---------------------------------------------------------------------------
// Wire constants
// ---------------------------------------------------------------------------

/// First header byte of every relay frame: the ASCII letter 'M' (Migration
/// Relay) so a stray non-migration frame fails fast instead of mis-parsing.
pub const frame_magic: u8 = 'M';

/// Frame format version stamped on newly-encoded frames. Bump when the
/// on-wire layout changes.
pub const frame_version: u8 = 2;

/// Oldest frame version `decodeFrame` still accepts. When `frame_version`
/// bumps, KEEP this at the previous version for at least one deploy cycle and
/// add a legacy decode arm (the Helix `.clients`/`.s2s_link` discipline):
/// during a rolling deploy the mesh runs mixed versions, and a bare equality
/// check silently drops every cross-node migration for the whole window.
pub const min_frame_version: u8 = 2;

/// Fixed frame header byte count: magic + version + fsm_state + u32 token_len.
pub const frame_header_len: usize = 1 + 1 + 1 + 4;

/// Upper bound on a decoded relay frame, mirroring the S2S frame ceiling. Large
/// enough for a full session snapshot, small enough to reject hostile inputs.
pub const max_frame_len: usize = 1024 * 1024;

const endian: std.builtin.Endian = .little;

pub const KeyPair = signed_object.KeyPair;
pub const PublicKey = signed_object.PublicKey;
pub const Signature = signed_object.Signature;
pub const CapsuleHash = [Sha256.digest_length]u8;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failures surfaced by the relay API. Allocation failures propagate via the
/// embedded `Allocator.Error`.
pub const Error = std.mem.Allocator.Error || error{
    /// Frame shorter than its own declared structure.
    Truncated,
    /// Bytes left over after a complete frame — a framing bug or attack.
    TrailingBytes,
    /// Header magic byte did not match `frame_magic`.
    BadMagic,
    /// Frame version this build does not understand.
    UnsupportedVersion,
    /// FSM state byte outside the known set.
    BadFsmState,
    /// Declared token length exceeds the frame or the size ceiling.
    OversizeFrame,
    /// Token's signature did not verify against the pinned origin key.
    BadSignature,
    /// Token payload did not decode to the expected CoilPack shape.
    MalformedToken,
    /// Capsule payload did not decode to the expected CoilPack shape.
    MalformedCapsule,
    /// Token's account did not match the capsule's account.
    AccountMismatch,
    /// Policy/journal rejected the migration as a replay or duplicate.
    Replay,
    /// Migration was not pre-registered with the origin's policy.
    NotRegistered,
};

// ---------------------------------------------------------------------------
// Migration FSM state
// ---------------------------------------------------------------------------

/// Lifecycle of a single migration as it crosses the wire. The state travels in
/// the frame header so the target can reject out-of-phase frames.
pub const FsmState = enum(u8) {
    /// Origin has minted the token and is offering the session.
    offered = 0x01,
    /// Target has accepted and restored the snapshot.
    accepted = 0x02,
    /// Reconnecting client has reclaimed the migrated session on the target.
    reclaimed = 0x03,

    pub fn tag(self: FsmState) u8 {
        return @intFromEnum(self);
    }

    pub fn fromTag(tag_value: u8) ?FsmState {
        return switch (tag_value) {
            @intFromEnum(FsmState.offered) => .offered,
            @intFromEnum(FsmState.accepted) => .accepted,
            @intFromEnum(FsmState.reclaimed) => .reclaimed,
            else => null,
        };
    }
};

// ---------------------------------------------------------------------------
// Snapshot — the session state to restore on the target
// ---------------------------------------------------------------------------

/// A point-in-time view of a logged-in session, sufficient to recreate it on a
/// new node. Borrowed slices on construction; owned slices after `decode`.
///
/// The field set mirrors `helix/session_snapshot.zig` (the local Helix-upgrade
/// snapshot) so a cross-machine migration restores the same recognizable session
/// a same-machine UPGRADE does: identity (nick/realname/account/host), away
/// state, oper status, user modes, and channel membership with status bits.
pub const Snapshot = struct {
    /// Client nickname at migration time.
    nick: []const u8,
    /// User modes, as an already-rendered mode string (e.g. "+iwx").
    umodes: []const u8,
    /// Channels the client occupies, by name.
    channels: []const []const u8,
    /// Per-channel member mode bits, aligned with `channels`.
    channel_modes: []const u8 = &.{},
    /// GECOS / realname.
    realname: []const u8 = "",
    /// Visible (cloaked) host the client presents.
    host: []const u8 = "",
    /// Authenticated account name ("" when not logged in).
    account: []const u8 = "",
    /// Away message ("" = not away; any non-empty value = away with that text).
    away: []const u8 = "",
    /// The client's USER ident, carried so a reclaimed session keeps its real
    /// ident instead of falling back to "user". "" when unknown.
    username: []const u8 = "",
    /// Whether the migrating session held operator status.
    is_oper: bool = false,

    /// Canonically encode the snapshot into owned CoilPack bytes.
    pub fn encode(self: Snapshot, allocator: std.mem.Allocator) Error![]u8 {
        // Build the channel array as CoilPack string values.
        var chan_values = try allocator.alloc(cpv.Value, self.channels.len);
        defer allocator.free(chan_values);
        var mode_values = try allocator.alloc(cpv.Value, self.channels.len);
        defer allocator.free(mode_values);
        for (self.channels, 0..) |chan, i| {
            chan_values[i] = .{ .string = chan };
            const modes: u8 = if (i < self.channel_modes.len) self.channel_modes[i] else 0;
            mode_values[i] = .{ .unsigned = modes };
        }

        var entries = [_]cpv.MapEntry{
            .{ .key = "account", .value = .{ .string = self.account } },
            .{ .key = "away", .value = .{ .string = self.away } },
            .{ .key = "channel_modes", .value = .{ .array = mode_values } },
            .{ .key = "channels", .value = .{ .array = chan_values } },
            .{ .key = "host", .value = .{ .string = self.host } },
            .{ .key = "is_oper", .value = .{ .unsigned = @intFromBool(self.is_oper) } },
            .{ .key = "nick", .value = .{ .string = self.nick } },
            .{ .key = "realname", .value = .{ .string = self.realname } },
            .{ .key = "umodes", .value = .{ .string = self.umodes } },
            .{ .key = "username", .value = .{ .string = self.username } },
        };
        return canonicalEncode(allocator, .{ .map = entries[0..] });
    }

    /// Decode an owned snapshot from CoilPack bytes. The returned snapshot owns
    /// its `nick`, `umodes`, identity strings, and each `channels` entry plus the
    /// outer slice. Release with `deinit`.
    pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!Snapshot {
        var value = cpv.Decoder.decode(allocator, bytes) catch return error.MalformedCapsule;
        defer value.deinit(allocator);
        if (value != .map) return error.MalformedCapsule;

        const nick_src = mapString(value.map, "nick") orelse return error.MalformedCapsule;
        const umodes_src = mapString(value.map, "umodes") orelse return error.MalformedCapsule;
        const chans_src = mapArray(value.map, "channels") orelse return error.MalformedCapsule;
        const modes_src = mapArray(value.map, "channel_modes");
        // Identity/state fields default to empty/false so an older-format capsule
        // missing them still decodes (forward-compatible widening).
        const realname_src = mapString(value.map, "realname") orelse "";
        const host_src = mapString(value.map, "host") orelse "";
        const account_src = mapString(value.map, "account") orelse "";
        const away_src = mapString(value.map, "away") orelse "";
        const username_src = mapString(value.map, "username") orelse "";
        const is_oper = (mapUnsigned(value.map, "is_oper") orelse 0) != 0;

        const nick = try allocator.dupe(u8, nick_src);
        errdefer allocator.free(nick);
        const umodes = try allocator.dupe(u8, umodes_src);
        errdefer allocator.free(umodes);
        const realname = try allocator.dupe(u8, realname_src);
        errdefer allocator.free(realname);
        const host = try allocator.dupe(u8, host_src);
        errdefer allocator.free(host);
        const account = try allocator.dupe(u8, account_src);
        errdefer allocator.free(account);
        const away = try allocator.dupe(u8, away_src);
        errdefer allocator.free(away);
        const username = try allocator.dupe(u8, username_src);
        errdefer allocator.free(username);

        var channels = try allocator.alloc([]const u8, chans_src.len);
        var filled: usize = 0;
        errdefer {
            for (channels[0..filled]) |chan| allocator.free(chan);
            allocator.free(channels);
        }
        var channel_modes = try allocator.alloc(u8, chans_src.len);
        errdefer allocator.free(channel_modes);
        @memset(channel_modes, 0);
        for (chans_src) |chan_value| {
            if (chan_value != .string) return error.MalformedCapsule;
            channels[filled] = try allocator.dupe(u8, chan_value.string);
            filled += 1;
        }
        if (modes_src) |mode_values| {
            if (mode_values.len != chans_src.len) return error.MalformedCapsule;
            for (mode_values, 0..) |mode_value, i| {
                if (mode_value != .unsigned or mode_value.unsigned > std.math.maxInt(u8)) return error.MalformedCapsule;
                channel_modes[i] = @intCast(mode_value.unsigned);
            }
        }

        return .{
            .nick = nick,
            .umodes = umodes,
            .channels = channels,
            .channel_modes = channel_modes,
            .realname = realname,
            .host = host,
            .account = account,
            .away = away,
            .username = username,
            .is_oper = is_oper,
        };
    }

    /// Release an owned snapshot returned by `decode`. Safe only on owned
    /// snapshots; never call on a borrowed-construction snapshot.
    pub fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.nick);
        allocator.free(self.umodes);
        allocator.free(self.realname);
        allocator.free(self.host);
        allocator.free(self.account);
        allocator.free(self.away);
        allocator.free(self.username);
        for (self.channels) |chan| allocator.free(chan);
        allocator.free(self.channels);
        allocator.free(self.channel_modes);
        self.* = undefined;
    }
};

// ---------------------------------------------------------------------------
// Token — the signed proof of a migration's authenticity and ownership
// ---------------------------------------------------------------------------

/// A signed migration token. The canonical bytes bind the account, a
/// deterministic nonce (the anti-replay identity), the FSM state at minting, and
/// an epoch counter. The Ed25519 signature over those bytes is what the target
/// verifies and what a reconnecting client reclaims.
pub const Token = struct {
    /// Account this token authorizes migrating.
    account: []const u8,
    /// Deterministic, caller-supplied nonce uniquely identifying this migration.
    nonce: u64,
    /// FSM state recorded at mint time.
    fsm_state: FsmState,
    /// Monotonic epoch; lets policy reject stale re-offers of the same nonce.
    epoch: u64,
    /// SHA-256 over the canonical capsule payload this token authorizes.
    capsule_hash: CapsuleHash,
    /// Ed25519 signature over the canonical token bytes.
    signature: Signature,
    /// Public key of the origin that signed it.
    signer: PublicKey,

    /// Release the owned account slice.
    pub fn deinit(self: *Token, allocator: std.mem.Allocator) void {
        allocator.free(self.account);
        self.* = undefined;
    }

    /// Canonical CoilPack value over the *signed* fields (everything except the
    /// signature itself). Stable regardless of map ordering, so the signature is
    /// reproducible. Caller-supplied account is borrowed into the value.
    fn canonicalValue(
        account: []const u8,
        nonce: u64,
        fsm_state: FsmState,
        epoch: u64,
        capsule_hash: []const u8,
    ) [5]cpv.MapEntry {
        return .{
            .{ .key = "account", .value = .{ .string = account } },
            .{ .key = "capsule_hash", .value = .{ .bytes = capsule_hash } },
            .{ .key = "epoch", .value = .{ .unsigned = epoch } },
            .{ .key = "fsm", .value = .{ .unsigned = fsm_state.tag() } },
            .{ .key = "nonce", .value = .{ .unsigned = nonce } },
        };
    }

    /// Mint a signed token from the given fields using the origin keypair. The
    /// returned token owns a copy of `account`.
    pub fn mint(
        allocator: std.mem.Allocator,
        kp: KeyPair,
        account: []const u8,
        nonce: u64,
        fsm_state: FsmState,
        epoch: u64,
        capsule_hash: CapsuleHash,
    ) Error!Token {
        var entries = canonicalValue(account, nonce, fsm_state, epoch, capsule_hash[0..]);
        var obj = signed_object.sign(allocator, .{ .map = entries[0..] }, kp) catch |err| {
            return narrowSignError(err);
        };
        defer obj.deinit(allocator);

        const owned_account = try allocator.dupe(u8, account);
        return .{
            .account = owned_account,
            .nonce = nonce,
            .fsm_state = fsm_state,
            .epoch = epoch,
            .capsule_hash = capsule_hash,
            .signature = obj.signature,
            .signer = obj.signer,
        };
    }

    /// Verify this token's signature against `expected_signer` by recomputing
    /// the canonical bytes from its fields. Returns `false` on any mismatch.
    pub fn verify(self: Token, allocator: std.mem.Allocator, expected_signer: PublicKey) bool {
        var entries = canonicalValue(self.account, self.nonce, self.fsm_state, self.epoch, self.capsule_hash[0..]);
        const canonical = cpv.Encoder.encode(allocator, .{ .map = entries[0..] }) catch return false;
        defer allocator.free(canonical);

        const obj = signed_object.SignedObject{
            .canonical = canonical,
            .signature = self.signature,
            .signer = self.signer,
        };
        return signed_object.verify(obj, expected_signer);
    }

    /// Constant-time equality over the bytes that identify ownership: the
    /// signature and signer. Two tokens for the same minted migration compare
    /// equal; anything else fails without leaking *where* it differs.
    pub fn sameProof(self: Token, other: Token) bool {
        const sig_eq = secure_fns.ctEq(self.signature[0..], other.signature[0..]);
        const signer_eq = secure_fns.ctEq(self.signer[0..], other.signer[0..]);
        // AND without an early branch so timing reflects neither result alone.
        return sig_eq and signer_eq;
    }

    /// Serialize the token to owned CoilPack bytes for embedding in a frame.
    pub fn encode(self: Token, allocator: std.mem.Allocator) Error![]u8 {
        var entries = [_]cpv.MapEntry{
            .{ .key = "account", .value = .{ .string = self.account } },
            .{ .key = "capsule_hash", .value = .{ .bytes = self.capsule_hash[0..] } },
            .{ .key = "epoch", .value = .{ .unsigned = self.epoch } },
            .{ .key = "fsm", .value = .{ .unsigned = self.fsm_state.tag() } },
            .{ .key = "nonce", .value = .{ .unsigned = self.nonce } },
            .{ .key = "sig", .value = .{ .bytes = self.signature[0..] } },
            .{ .key = "signer", .value = .{ .bytes = self.signer[0..] } },
        };
        return canonicalEncode(allocator, .{ .map = entries[0..] });
    }

    /// Decode an owned token from CoilPack bytes.
    pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!Token {
        var value = cpv.Decoder.decode(allocator, bytes) catch return error.MalformedToken;
        defer value.deinit(allocator);
        if (value != .map) return error.MalformedToken;

        const account_src = mapString(value.map, "account") orelse return error.MalformedToken;
        const epoch = mapUnsigned(value.map, "epoch") orelse return error.MalformedToken;
        const fsm_raw = mapUnsigned(value.map, "fsm") orelse return error.MalformedToken;
        const nonce = mapUnsigned(value.map, "nonce") orelse return error.MalformedToken;
        const capsule_hash_src = mapBytes(value.map, "capsule_hash") orelse return error.MalformedToken;
        const sig_src = mapBytes(value.map, "sig") orelse return error.MalformedToken;
        const signer_src = mapBytes(value.map, "signer") orelse return error.MalformedToken;

        if (fsm_raw > std.math.maxInt(u8)) return error.MalformedToken;
        const fsm_state = FsmState.fromTag(@intCast(fsm_raw)) orelse return error.MalformedToken;
        if (capsule_hash_src.len != Sha256.digest_length) return error.MalformedToken;
        if (sig_src.len != @typeInfo(Signature).array.len) return error.MalformedToken;
        if (signer_src.len != @typeInfo(PublicKey).array.len) return error.MalformedToken;

        const owned_account = try allocator.dupe(u8, account_src);
        errdefer allocator.free(owned_account);

        var signature: Signature = undefined;
        @memcpy(signature[0..], sig_src);
        var signer: PublicKey = undefined;
        @memcpy(signer[0..], signer_src);
        var capsule_hash: CapsuleHash = undefined;
        @memcpy(capsule_hash[0..], capsule_hash_src);

        return .{
            .account = owned_account,
            .nonce = nonce,
            .fsm_state = fsm_state,
            .epoch = epoch,
            .capsule_hash = capsule_hash,
            .signature = signature,
            .signer = signer,
        };
    }
};

/// Narrow the open error set returned by `signed_object.sign` (which surfaces
/// CoilPack format errors that cannot occur for our well-formed input) down to
/// the relay's closed `Error`. Allocation failure is the only realistic case.
fn narrowSignError(err: anyerror) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        // Our canonical value is always well-formed (ASCII keys, valid UTF-8
        // account already validated by the caller), so any other error is a
        // logic bug surfacing as a malformed token rather than a crash.
        else => error.MalformedToken,
    };
}

// ---------------------------------------------------------------------------
// Capsule — {token, account, snapshot}
// ---------------------------------------------------------------------------

/// The migration capsule that travels inside a relay frame: a signed token, the
/// account being migrated, and the session snapshot to restore. After `decode`
/// every field is owned; release with `deinit`.
pub const Capsule = struct {
    token: Token,
    account: []const u8,
    snapshot: Snapshot,

    /// Release every owned field.
    pub fn deinit(self: *Capsule, allocator: std.mem.Allocator) void {
        self.token.deinit(allocator);
        allocator.free(self.account);
        self.snapshot.deinit(allocator);
        self.* = undefined;
    }

    /// Encode the capsule (token bytes + account + snapshot bytes) into owned
    /// CoilPack bytes. The token is embedded as its own encoded blob so the
    /// outer capsule and the token evolve independently.
    pub fn encode(self: Capsule, allocator: std.mem.Allocator) Error![]u8 {
        const token_bytes = try self.token.encode(allocator);
        defer allocator.free(token_bytes);
        const snapshot_bytes = try self.snapshot.encode(allocator);
        defer allocator.free(snapshot_bytes);

        var entries = [_]cpv.MapEntry{
            .{ .key = "account", .value = .{ .string = self.account } },
            .{ .key = "snapshot", .value = .{ .bytes = snapshot_bytes } },
            .{ .key = "token", .value = .{ .bytes = token_bytes } },
        };
        return canonicalEncode(allocator, .{ .map = entries[0..] });
    }

    /// Decode an owned capsule from CoilPack bytes.
    pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!Capsule {
        var value = cpv.Decoder.decode(allocator, bytes) catch return error.MalformedCapsule;
        defer value.deinit(allocator);
        if (value != .map) return error.MalformedCapsule;

        const account_src = mapString(value.map, "account") orelse return error.MalformedCapsule;
        const snapshot_src = mapBytes(value.map, "snapshot") orelse return error.MalformedCapsule;
        const token_src = mapBytes(value.map, "token") orelse return error.MalformedCapsule;

        var token = try Token.decode(allocator, token_src);
        errdefer token.deinit(allocator);

        const account = try allocator.dupe(u8, account_src);
        errdefer allocator.free(account);

        var snapshot = try Snapshot.decode(allocator, snapshot_src);
        errdefer snapshot.deinit(allocator);

        return .{ .token = token, .account = account, .snapshot = snapshot };
    }
};

// ---------------------------------------------------------------------------
// Relay frame — the typed envelope that carries a capsule between peers
// ---------------------------------------------------------------------------

/// On-wire layout of a migration relay frame:
///
///   [0]      u8   frame_magic
///   [1]      u8   frame_version
///   [2]      u8   fsm_state (FsmState tag)
///   [3..7]   u32  token_len (little-endian)
///   [7..]    token_len bytes  : the encoded `Token`
///   [..end]  rest             : the encoded `Capsule`
///
/// The token is hoisted out of the capsule's opaque blob so a relay can verify
/// it without fully decoding the (larger) capsule, and the FSM state rides in
/// the clear so out-of-phase frames are rejected before any crypto work.
pub const Frame = struct {
    fsm_state: FsmState,
    token: Token,
    capsule: Capsule,

    /// Release the owned token and capsule.
    pub fn deinit(self: *Frame, allocator: std.mem.Allocator) void {
        self.token.deinit(allocator);
        self.capsule.deinit(allocator);
        self.* = undefined;
    }
};

/// Encode a relay frame carrying `capsule` at `fsm_state`. The frame's hoisted
/// token is taken from the capsule's token. Returns owned bytes.
pub fn encodeFrame(allocator: std.mem.Allocator, fsm_state: FsmState, capsule: Capsule) Error![]u8 {
    const token_bytes = try capsule.token.encode(allocator);
    defer allocator.free(token_bytes);
    const capsule_bytes = try capsule.encode(allocator);
    defer allocator.free(capsule_bytes);

    if (token_bytes.len > std.math.maxInt(u32)) return error.OversizeFrame;
    const total = frame_header_len + token_bytes.len + capsule_bytes.len;
    if (total > max_frame_len) return error.OversizeFrame;

    var out = try allocator.alloc(u8, total);
    errdefer allocator.free(out);

    out[0] = frame_magic;
    out[1] = frame_version;
    out[2] = fsm_state.tag();
    std.mem.writeInt(u32, out[3..7], @intCast(token_bytes.len), endian);
    @memcpy(out[frame_header_len .. frame_header_len + token_bytes.len], token_bytes);
    @memcpy(out[frame_header_len + token_bytes.len ..], capsule_bytes);

    return out;
}

/// Decode a relay frame from `bytes`. Validates the header, then decodes the
/// hoisted token and the capsule. Returns an owned `Frame`; release with
/// `deinit`. Does NOT verify the signature or consult policy — that is the
/// target's job in `accept`.
pub fn decodeFrame(allocator: std.mem.Allocator, bytes: []const u8) Error!Frame {
    if (bytes.len < frame_header_len) return error.Truncated;
    if (bytes.len > max_frame_len) return error.OversizeFrame;
    if (bytes[0] != frame_magic) return error.BadMagic;
    // Version-aware layout dispatch, never a bare `!= frame_version` equality:
    // each accepted version gets its own arm so a future v3 encoder change is
    // FORCED to add a v2 legacy arm here (rolling-deploy interop) instead of
    // rejecting every frame from a not-yet-upgraded peer. Versions outside
    // [min_frame_version, frame_version] fail closed.
    switch (bytes[1]) {
        2 => {}, // v2: the first shipped layout — decoded below.
        else => return error.UnsupportedVersion,
    }

    const fsm_state = FsmState.fromTag(bytes[2]) orelse return error.BadFsmState;
    const token_len: usize = @intCast(std.mem.readInt(u32, bytes[3..7], endian));

    const token_start = frame_header_len;
    const token_end = std.math.add(usize, token_start, token_len) catch return error.OversizeFrame;
    if (token_end > bytes.len) return error.Truncated;

    var token = try Token.decode(allocator, bytes[token_start..token_end]);
    errdefer token.deinit(allocator);

    var capsule = try Capsule.decode(allocator, bytes[token_end..]);
    errdefer capsule.deinit(allocator);

    return .{ .fsm_state = fsm_state, .token = token, .capsule = capsule };
}

// ---------------------------------------------------------------------------
// Journal — append-only record of seen migration nonces (replay defense)
// ---------------------------------------------------------------------------

/// Records which migration nonces a node has already processed, so a replayed or
/// duplicated frame is rejected. Pure in-memory; the server may persist its
/// contents out of band but the relay never touches storage itself.
pub const Journal = struct {
    /// Set of nonces already consumed, keyed by nonce.
    seen: std.AutoHashMapUnmanaged(u64, void) = .empty,

    pub fn deinit(self: *Journal, allocator: std.mem.Allocator) void {
        self.seen.deinit(allocator);
        self.* = undefined;
    }

    /// Records `nonce`. Returns `true` if it was newly recorded, `false` if it
    /// had already been seen (i.e. this is a replay).
    pub fn record(self: *Journal, allocator: std.mem.Allocator, nonce: u64) Error!bool {
        const gop = try self.seen.getOrPut(allocator, nonce);
        if (gop.found_existing) return false;
        gop.value_ptr.* = {};
        return true;
    }

    /// Reports whether `nonce` has already been recorded.
    pub fn contains(self: *const Journal, nonce: u64) bool {
        return self.seen.contains(nonce);
    }
};

// ---------------------------------------------------------------------------
// Policy — pending-migration ledger keyed by account
// ---------------------------------------------------------------------------

/// Tracks the highest epoch admitted per account, so a re-offer of an old epoch
/// for the same account is rejected as stale even if its nonce is fresh. Keys
/// are owned account strings.
pub const Policy = struct {
    /// account -> highest epoch admitted so far.
    epochs: std.StringHashMapUnmanaged(u64) = .empty,

    pub fn deinit(self: *Policy, allocator: std.mem.Allocator) void {
        var it = self.epochs.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        self.epochs.deinit(allocator);
        self.* = undefined;
    }

    /// Admit `epoch` for `account`. Returns `true` if it is strictly newer than
    /// any previously admitted epoch (or the first for this account); `false` if
    /// it is stale or a repeat. Owns a copy of `account` on first admission.
    pub fn admit(self: *Policy, allocator: std.mem.Allocator, account: []const u8, epoch: u64) Error!bool {
        const gop = try self.epochs.getOrPut(allocator, account);
        if (!gop.found_existing) {
            const owned = allocator.dupe(u8, account) catch |err| {
                self.epochs.removeByPtr(gop.key_ptr);
                return err;
            };
            gop.key_ptr.* = owned;
            gop.value_ptr.* = epoch;
            return true;
        }
        if (epoch <= gop.value_ptr.*) return false;
        gop.value_ptr.* = epoch;
        return true;
    }

    /// Highest epoch admitted for `account`, if any.
    pub fn current(self: *const Policy, account: []const u8) ?u64 {
        return self.epochs.get(account);
    }
};

// ---------------------------------------------------------------------------
// Metrics — counters the relay bumps as frames flow
// ---------------------------------------------------------------------------

/// Lightweight counters the relay updates so the server can observe migration
/// throughput and rejections without instrumenting call sites.
pub const Metrics = struct {
    prepared: u64 = 0,
    accepted: u64 = 0,
    rejected_signature: u64 = 0,
    rejected_replay: u64 = 0,
    reclaimed: u64 = 0,
};

// ---------------------------------------------------------------------------
// MigrationOrigin — the sending side
// ---------------------------------------------------------------------------

/// What `MigrationOrigin.prepare` hands back: the wire bytes to send and the
/// token (so the origin can correlate the eventual accept). The bytes are owned
/// by the caller; the token is owned and must be `deinit`'d.
pub const PreparedMigration = struct {
    frame_bytes: []u8,
    token: Token,

    pub fn deinit(self: *PreparedMigration, allocator: std.mem.Allocator) void {
        allocator.free(self.frame_bytes);
        self.token.deinit(allocator);
        self.* = undefined;
    }
};

/// The origin (sending) side of a migration. Holds the signing keypair, a
/// policy ledger, a journal, and metrics. Pure: it produces frame bytes, never
/// I/O.
pub const MigrationOrigin = struct {
    allocator: std.mem.Allocator,
    keypair: KeyPair,
    policy: Policy = .{},
    journal: Journal = .{},
    metrics: Metrics = .{},

    pub fn init(allocator: std.mem.Allocator, keypair: KeyPair) MigrationOrigin {
        return .{ .allocator = allocator, .keypair = keypair };
    }

    pub fn deinit(self: *MigrationOrigin) void {
        self.policy.deinit(self.allocator);
        self.journal.deinit(self.allocator);
        self.* = undefined;
    }

    /// The origin's public key, which the target must pin as the expected
    /// signer.
    pub fn publicKey(self: *const MigrationOrigin) PublicKey {
        return self.keypair.public_key.toBytes();
    }

    /// Prepare a migration of `account`'s `snapshot`. Mints a signed token at
    /// `nonce`/`epoch`, records the pending migration in the policy and journal,
    /// builds the capsule, and serializes the offer frame.
    ///
    /// `nonce` must be a deterministic, caller-supplied unique value (e.g. a
    /// session id or counter); the relay never draws randomness itself.
    ///
    /// Returns `error.Replay` if this nonce was already prepared, or if the
    /// epoch is stale for the account.
    pub fn prepare(
        self: *MigrationOrigin,
        account: []const u8,
        snapshot: Snapshot,
        nonce: u64,
        epoch: u64,
    ) Error!PreparedMigration {
        // Policy + journal first, so a rejected offer mints nothing.
        if (!try self.policy.admit(self.allocator, account, epoch)) return error.Replay;
        if (!try self.journal.record(self.allocator, nonce)) return error.Replay;

        const capsule_hash = try capsulePayloadHash(self.allocator, account, snapshot);

        var token = try Token.mint(self.allocator, self.keypair, account, nonce, .offered, epoch, capsule_hash);
        errdefer token.deinit(self.allocator);

        // The capsule's snapshot must be owned independently of the caller's, so
        // re-encode/decode through CoilPack to deep-copy it.
        const snap_bytes = try snapshot.encode(self.allocator);
        defer self.allocator.free(snap_bytes);

        var capsule = blk: {
            // The capsule borrows the token's owned fields by value-copying the
            // struct; we keep an independent owned token to return, so re-mint a
            // matching token copy for the capsule rather than aliasing the slice.
            var capsule_token = try Token.mint(self.allocator, self.keypair, account, nonce, .offered, epoch, capsule_hash);
            errdefer capsule_token.deinit(self.allocator);

            const owned_account = try self.allocator.dupe(u8, account);
            errdefer self.allocator.free(owned_account);

            var capsule_snapshot = try Snapshot.decode(self.allocator, snap_bytes);
            errdefer capsule_snapshot.deinit(self.allocator);

            break :blk Capsule{
                .token = capsule_token,
                .account = owned_account,
                .snapshot = capsule_snapshot,
            };
        };
        defer capsule.deinit(self.allocator);

        const frame_bytes = try encodeFrame(self.allocator, .offered, capsule);
        errdefer self.allocator.free(frame_bytes);

        self.metrics.prepared += 1;
        return .{ .frame_bytes = frame_bytes, .token = token };
    }
};

// ---------------------------------------------------------------------------
// MigrationTarget — the receiving side
// ---------------------------------------------------------------------------

/// The target (receiving) side. Pins the origin's public key, keeps its own
/// policy/journal for replay defense, records metrics, and stores reclaim tokens
/// so a reconnecting client can prove ownership of the migrated session.
pub const MigrationTarget = struct {
    allocator: std.mem.Allocator,
    expected_signer: PublicKey,
    policy: Policy = .{},
    journal: Journal = .{},
    metrics: Metrics = .{},
    /// account -> the token a reconnecting client must reclaim. Keys and the
    /// stored token's account slice are owned.
    reclaimable: std.StringHashMapUnmanaged(Token) = .empty,

    pub fn init(allocator: std.mem.Allocator, expected_signer: PublicKey) MigrationTarget {
        return .{ .allocator = allocator, .expected_signer = expected_signer };
    }

    pub fn deinit(self: *MigrationTarget) void {
        self.policy.deinit(self.allocator);
        self.journal.deinit(self.allocator);
        var it = self.reclaimable.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.reclaimable.deinit(self.allocator);
        self.* = undefined;
    }

    /// Accept an incoming offer frame. Decodes it, verifies the token signature
    /// against the pinned signer, cross-checks token/capsule account agreement,
    /// enforces replay (journal) and stale-epoch (policy) rejection, stores the
    /// reclaim token, bumps metrics, and returns the owned `Capsule` whose
    /// snapshot the server restores.
    ///
    /// On any rejection no reclaim token is stored and the relevant metric is
    /// bumped. The caller owns the returned capsule and must `deinit` it.
    pub fn accept(self: *MigrationTarget, frame_bytes: []const u8) Error!Capsule {
        var frame = try decodeFrame(self.allocator, frame_bytes);
        // We move the capsule out on success; otherwise free both halves.
        errdefer frame.deinit(self.allocator);

        // Signature verification against the pinned origin key.
        if (!frame.token.verify(self.allocator, self.expected_signer)) {
            self.metrics.rejected_signature += 1;
            return error.BadSignature;
        }

        // Token and capsule must agree on the account, or someone spliced a
        // valid token onto a foreign capsule.
        if (!std.mem.eql(u8, frame.token.account, frame.capsule.account)) {
            self.metrics.rejected_signature += 1;
            return error.AccountMismatch;
        }
        const capsule_hash = try capsulePayloadHash(self.allocator, frame.capsule.account, frame.capsule.snapshot);
        if (!std.crypto.timing_safe.eql(CapsuleHash, frame.token.capsule_hash, capsule_hash)) {
            self.metrics.rejected_signature += 1;
            return error.BadSignature;
        }

        // Stale-epoch rejection (policy), then replay rejection (journal).
        if (!try self.policy.admit(self.allocator, frame.token.account, frame.token.epoch)) {
            self.metrics.rejected_replay += 1;
            return error.Replay;
        }
        if (!try self.journal.record(self.allocator, frame.token.nonce)) {
            self.metrics.rejected_replay += 1;
            return error.Replay;
        }

        // Store a reclaim token (a fresh owned copy) keyed by account so a
        // reconnecting client can prove ownership.
        try self.storeReclaim(frame.token);

        self.metrics.accepted += 1;

        // Hand the capsule to the caller; detach it from the frame so our
        // errdefer does not also free it. The frame's hoisted token is freed
        // here since the capsule carries its own independent token copy.
        const capsule = frame.capsule;
        frame.token.deinit(self.allocator);
        return capsule;
    }

    /// Store (or replace) the reclaim token for an account. Owns a copy.
    fn storeReclaim(self: *MigrationTarget, token: Token) Error!void {
        var copy = try cloneToken(self.allocator, token);
        errdefer copy.deinit(self.allocator);

        const gop = try self.reclaimable.getOrPut(self.allocator, token.account);
        if (gop.found_existing) {
            // Replace the previously-stored token; reuse the existing owned key.
            gop.value_ptr.deinit(self.allocator);
            gop.value_ptr.* = copy;
            return;
        }
        const owned_key = self.allocator.dupe(u8, token.account) catch |err| {
            self.reclaimable.removeByPtr(gop.key_ptr);
            return err;
        };
        gop.key_ptr.* = owned_key;
        gop.value_ptr.* = copy;
    }

    /// Return the reclaim token a reconnecting client on this target must
    /// present to prove it owns the migrated session for `account`, or `null` if
    /// no migration is pending for that account. The returned token is owned by
    /// the caller and must be `deinit`'d.
    pub fn reclaimToken(self: *MigrationTarget, account: []const u8) Error!?Token {
        const stored = self.reclaimable.getPtr(account) orelse return null;
        self.metrics.reclaimed += 1;
        return try cloneToken(self.allocator, stored.*);
    }

    /// Verify that `presented` matches the stored reclaim token for `account`,
    /// using a constant-time proof comparison. Returns `false` if no migration
    /// is pending or the proof does not match.
    pub fn verifyReclaim(self: *MigrationTarget, account: []const u8, presented: Token) bool {
        const stored = self.reclaimable.getPtr(account) orelse return false;
        // Account must also match the presented token, constant-time.
        if (!secure_fns.ctEq(account, presented.account)) return false;
        return stored.sameProof(presented);
    }
};

/// Deep-copy a token, duplicating its owned account slice.
fn cloneToken(allocator: std.mem.Allocator, token: Token) Error!Token {
    const account = try allocator.dupe(u8, token.account);
    return .{
        .account = account,
        .nonce = token.nonce,
        .fsm_state = token.fsm_state,
        .epoch = token.epoch,
        .capsule_hash = token.capsule_hash,
        .signature = token.signature,
        .signer = token.signer,
    };
}

fn capsulePayloadHash(allocator: std.mem.Allocator, account: []const u8, snapshot: Snapshot) Error!CapsuleHash {
    const snapshot_bytes = try snapshot.encode(allocator);
    defer allocator.free(snapshot_bytes);

    var entries = [_]cpv.MapEntry{
        .{ .key = "account", .value = .{ .string = account } },
        .{ .key = "snapshot", .value = .{ .bytes = snapshot_bytes } },
    };
    const canonical = try canonicalEncode(allocator, .{ .map = entries[0..] });
    defer allocator.free(canonical);

    var digest: CapsuleHash = undefined;
    Sha256.hash(canonical, &digest, .{});
    return digest;
}

// ---------------------------------------------------------------------------
// CoilPack map helpers
// ---------------------------------------------------------------------------

/// Canonically encode a CoilPack value, narrowing the encoder's open error set
/// (which can surface format errors like InvalidUtf8 for malformed input) into
/// the relay's closed `Error`. Well-formed daemon input never trips those, so a
/// format error is reported as a malformed capsule rather than crashing.
fn canonicalEncode(allocator: std.mem.Allocator, value: cpv.Value) Error![]u8 {
    return cpv.Encoder.encode(allocator, value) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.MalformedCapsule,
    };
}

fn mapEntry(entries: []cpv.MapEntry, key: []const u8) ?cpv.Value {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.key, key)) return entry.value;
    }
    return null;
}

fn mapString(entries: []cpv.MapEntry, key: []const u8) ?[]const u8 {
    const value = mapEntry(entries, key) orelse return null;
    return if (value == .string) value.string else null;
}

fn mapBytes(entries: []cpv.MapEntry, key: []const u8) ?[]const u8 {
    const value = mapEntry(entries, key) orelse return null;
    return if (value == .bytes) value.bytes else null;
}

fn mapUnsigned(entries: []cpv.MapEntry, key: []const u8) ?u64 {
    const value = mapEntry(entries, key) orelse return null;
    return if (value == .unsigned) value.unsigned else null;
}

fn mapArray(entries: []cpv.MapEntry, key: []const u8) ?[]cpv.Value {
    const value = mapEntry(entries, key) orelse return null;
    return if (value == .array) value.array else null;
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

/// Deterministic Ed25519 keypair from a single seed byte. No CSPRNG.
fn testKey(seed: u8) !KeyPair {
    const Ed25519 = std.crypto.sign.Ed25519;
    return KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(seed)));
}

fn sampleSnapshot() Snapshot {
    const channels = [_][]const u8{ "#orochi", "#helix" };
    return .{
        .nick = "kain",
        .umodes = "+iwx",
        .channels = channels[0..],
        .realname = "Kain Example",
        .host = "cloak-ab12.orochi",
        .account = "kain",
        .away = "biab",
        .is_oper = true,
    };
}

test "origin.prepare -> target.accept round-trips a snapshot" {
    // Arrange
    const allocator = testing.allocator;
    const kp = try testKey(0x11);

    var origin = MigrationOrigin.init(allocator, kp);
    defer origin.deinit();
    var target = MigrationTarget.init(allocator, origin.publicKey());
    defer target.deinit();

    const channels = [_][]const u8{ "#orochi", "#helix" };
    const snapshot = Snapshot{
        .nick = "kain",
        .umodes = "+iwx",
        .channels = channels[0..],
        .realname = "Kain Example",
        .host = "cloak-ab12.orochi",
        .account = "kain",
        .away = "biab",
        .username = "webchat",
        .is_oper = true,
    };

    // Act
    var prepared = try origin.prepare("kain", snapshot, 0xABCD, 1);
    defer prepared.deinit(allocator);

    var capsule = try target.accept(prepared.frame_bytes);
    defer capsule.deinit(allocator);

    // Assert: the snapshot survived the round-trip intact.
    try testing.expectEqualStrings("kain", capsule.snapshot.nick);
    try testing.expectEqualStrings("+iwx", capsule.snapshot.umodes);
    try testing.expectEqual(@as(usize, 2), capsule.snapshot.channels.len);
    try testing.expectEqualStrings("#orochi", capsule.snapshot.channels[0]);
    try testing.expectEqualStrings("#helix", capsule.snapshot.channels[1]);
    // The widened identity/state fields survive too.
    try testing.expectEqualStrings("Kain Example", capsule.snapshot.realname);
    try testing.expectEqualStrings("cloak-ab12.orochi", capsule.snapshot.host);
    try testing.expectEqualStrings("kain", capsule.snapshot.account);
    try testing.expectEqualStrings("biab", capsule.snapshot.away);
    try testing.expectEqualStrings("webchat", capsule.snapshot.username);
    try testing.expect(capsule.snapshot.is_oper);
    try testing.expectEqualStrings("kain", capsule.account);
    try testing.expectEqual(@as(u64, 0xABCD), capsule.token.nonce);
    try testing.expectEqual(@as(u64, 1), origin.metrics.prepared);
    try testing.expectEqual(@as(u64, 1), target.metrics.accepted);
}

test "accept rejects a forged token signed by the wrong key" {
    // Arrange
    const allocator = testing.allocator;
    const real_kp = try testKey(0x22);
    const attacker_kp = try testKey(0x23);

    // Origin signs with the attacker key, but target pins the real key.
    var origin = MigrationOrigin.init(allocator, attacker_kp);
    defer origin.deinit();
    var target = MigrationTarget.init(allocator, real_kp.public_key.toBytes());
    defer target.deinit();

    const snapshot = sampleSnapshot();

    var prepared = try origin.prepare("kain", snapshot, 0x01, 1);
    defer prepared.deinit(allocator);

    // Act / Assert
    try testing.expectError(error.BadSignature, target.accept(prepared.frame_bytes));
    try testing.expectEqual(@as(u64, 1), target.metrics.rejected_signature);
    try testing.expectEqual(@as(u64, 0), target.metrics.accepted);
}

test "accept rejects a tampered token whose bytes were mutated in flight" {
    // Arrange
    const allocator = testing.allocator;
    const kp = try testKey(0x24);

    var origin = MigrationOrigin.init(allocator, kp);
    defer origin.deinit();
    var target = MigrationTarget.init(allocator, origin.publicKey());
    defer target.deinit();

    const snapshot = sampleSnapshot();
    var prepared = try origin.prepare("kain", snapshot, 0x02, 1);
    defer prepared.deinit(allocator);

    // Flip a byte inside the hoisted token region (past the fixed header).
    const tampered = try allocator.dupe(u8, prepared.frame_bytes);
    defer allocator.free(tampered);
    tampered[frame_header_len + 4] ^= 0x01;

    // Act / Assert: the mutated token must not yield an accepted migration.
    // Mutating a signed byte makes the Ed25519 signature fail to verify.
    if (target.accept(tampered)) |capsule| {
        var c = capsule;
        c.deinit(allocator);
        try testing.expect(false); // a tampered token must never be accepted
    } else |err| {
        try testing.expect(err == error.BadSignature or err == error.MalformedToken);
    }
    try testing.expectEqual(@as(u64, 0), target.metrics.accepted);
}

test "policy/journal reject a replayed duplicate migration" {
    // Arrange
    const allocator = testing.allocator;
    const kp = try testKey(0x33);

    var origin = MigrationOrigin.init(allocator, kp);
    defer origin.deinit();
    var target = MigrationTarget.init(allocator, origin.publicKey());
    defer target.deinit();

    const snapshot = sampleSnapshot();

    // First migration accepted normally.
    var prepared = try origin.prepare("kain", snapshot, 0xFEED, 1);
    defer prepared.deinit(allocator);
    var capsule = try target.accept(prepared.frame_bytes);
    defer capsule.deinit(allocator);

    // Act / Assert: replaying the identical frame is rejected by the target's
    // journal/policy.
    try testing.expectError(error.Replay, target.accept(prepared.frame_bytes));
    try testing.expectEqual(@as(u64, 1), target.metrics.accepted);
    try testing.expectEqual(@as(u64, 1), target.metrics.rejected_replay);

    // And the origin refuses to re-prepare the same nonce/epoch.
    try testing.expectError(error.Replay, origin.prepare("kain", snapshot, 0xFEED, 1));
}

test "reclaimToken matches only the right account" {
    // Arrange
    const allocator = testing.allocator;
    const kp = try testKey(0x44);

    var origin = MigrationOrigin.init(allocator, kp);
    defer origin.deinit();
    var target = MigrationTarget.init(allocator, origin.publicKey());
    defer target.deinit();

    const snapshot = sampleSnapshot();
    var prepared = try origin.prepare("kain", snapshot, 0x77, 1);
    defer prepared.deinit(allocator);
    var capsule = try target.accept(prepared.frame_bytes);
    defer capsule.deinit(allocator);

    // Act
    var reclaimed = (try target.reclaimToken("kain")).?;
    defer reclaimed.deinit(allocator);

    // Assert: the right account yields a token that verifies as the same proof;
    // a different account yields nothing.
    try testing.expect(target.verifyReclaim("kain", reclaimed));
    try testing.expectEqual(@as(?Token, null), try target.reclaimToken("someone-else"));

    // A token for the right account but a forged proof must not verify.
    var forged = try cloneToken(allocator, reclaimed);
    defer forged.deinit(allocator);
    forged.signature[0] ^= 0xFF;
    try testing.expect(!target.verifyReclaim("kain", forged));
}

test "frame header rejects bad magic, version, and truncation" {
    // Arrange
    const allocator = testing.allocator;
    const kp = try testKey(0x55);
    var origin = MigrationOrigin.init(allocator, kp);
    defer origin.deinit();

    const snapshot = sampleSnapshot();
    var prepared = try origin.prepare("kain", snapshot, 0x88, 1);
    defer prepared.deinit(allocator);

    // Bad magic.
    {
        const buf = try allocator.dupe(u8, prepared.frame_bytes);
        defer allocator.free(buf);
        buf[0] ^= 0xFF;
        try testing.expectError(error.BadMagic, decodeFrame(allocator, buf));
    }
    // Bad version.
    {
        const buf = try allocator.dupe(u8, prepared.frame_bytes);
        defer allocator.free(buf);
        buf[1] = frame_version +% 1;
        try testing.expectError(error.UnsupportedVersion, decodeFrame(allocator, buf));
    }
    // Truncated below header.
    try testing.expectError(error.Truncated, decodeFrame(allocator, prepared.frame_bytes[0..3]));
}

test "decodeFrame rejects versions outside [min_frame_version, frame_version] on both sides" {
    // The supported range is a contract: a below-range (pre-history) version and
    // an above-range (future) version must BOTH fail closed. When frame_version
    // bumps to 3, this test forces the author to decide the v2 legacy arm
    // explicitly rather than letting a bare equality silently drop v2 peers.
    const allocator = testing.allocator;
    const kp = try testKey(0x66);
    var origin = MigrationOrigin.init(allocator, kp);
    defer origin.deinit();

    var prepared = try origin.prepare("kain", sampleSnapshot(), 0x99, 1);
    defer prepared.deinit(allocator);
    try testing.expectEqual(frame_version, prepared.frame_bytes[1]);
    try testing.expect(min_frame_version <= frame_version);

    const buf = try allocator.dupe(u8, prepared.frame_bytes);
    defer allocator.free(buf);

    buf[1] = min_frame_version - 1; // below the floor
    try testing.expectError(error.UnsupportedVersion, decodeFrame(allocator, buf));
    buf[1] = frame_version + 1; // above the ceiling
    try testing.expectError(error.UnsupportedVersion, decodeFrame(allocator, buf));

    // Every version inside the range decodes (today that is exactly v2).
    buf[1] = frame_version;
    var frame = try decodeFrame(allocator, buf);
    frame.deinit(allocator);
}

test "snapshot encode/decode round-trips an empty channel list" {
    // Arrange
    const allocator = testing.allocator;
    const empty: []const []const u8 = &.{};
    const snapshot = Snapshot{ .nick = "lone", .umodes = "+i", .channels = empty };

    // Act
    const bytes = try snapshot.encode(allocator);
    defer allocator.free(bytes);
    var decoded = try Snapshot.decode(allocator, bytes);
    defer decoded.deinit(allocator);

    // Assert: the unset identity/state fields default to empty/false.
    try testing.expectEqualStrings("lone", decoded.nick);
    try testing.expectEqualStrings("+i", decoded.umodes);
    try testing.expectEqual(@as(usize, 0), decoded.channels.len);
    try testing.expectEqual(@as(usize, 0), decoded.channel_modes.len);
    try testing.expectEqualStrings("", decoded.realname);
    try testing.expectEqualStrings("", decoded.host);
    try testing.expectEqualStrings("", decoded.account);
    try testing.expectEqualStrings("", decoded.away);
    try testing.expect(!decoded.is_oper);
}

test "snapshot encode/decode round-trips the widened identity + state fields" {
    // Arrange
    const allocator = testing.allocator;
    const channels = [_][]const u8{ "#ops", "#lounge", "#dev" };
    const channel_modes = [_]u8{ 0x01, 0x02, 0x04 };
    const snapshot = Snapshot{
        .nick = "alice",
        .umodes = "+iwxo",
        .channels = channels[0..],
        .channel_modes = channel_modes[0..],
        .realname = "Alice Liddell",
        .host = "cloak-1a2b.users.orochi",
        .account = "alice",
        .away = "in the rabbit hole",
        .is_oper = true,
    };

    // Act
    const bytes = try snapshot.encode(allocator);
    defer allocator.free(bytes);
    var decoded = try Snapshot.decode(allocator, bytes);
    defer decoded.deinit(allocator);

    // Assert: every field round-trips byte-for-byte.
    try testing.expectEqualStrings("alice", decoded.nick);
    try testing.expectEqualStrings("+iwxo", decoded.umodes);
    try testing.expectEqual(@as(usize, 3), decoded.channels.len);
    try testing.expectEqualStrings("#ops", decoded.channels[0]);
    try testing.expectEqualStrings("#lounge", decoded.channels[1]);
    try testing.expectEqualStrings("#dev", decoded.channels[2]);
    try testing.expectEqualSlices(u8, channel_modes[0..], decoded.channel_modes);
    try testing.expectEqualStrings("Alice Liddell", decoded.realname);
    try testing.expectEqualStrings("cloak-1a2b.users.orochi", decoded.host);
    try testing.expectEqualStrings("alice", decoded.account);
    try testing.expectEqualStrings("in the rabbit hole", decoded.away);
    try testing.expect(decoded.is_oper);
}
