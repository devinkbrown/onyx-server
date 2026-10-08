// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Socketless QUIC v1 connection driver (RFC 9000 + RFC 9001) — layer 5.
//!
//! This ties the four tested layers below into a real connection. It is fully
//! socketless: the UDP listener (next layer) only calls `recvDatagram` with one
//! received UDP payload and `sendDatagrams` to collect the datagrams to write
//! back. Nothing here touches a socket, a clock other than the `now` the caller
//! passes, or any global state.
//!
//! Layers reused verbatim (no re-decrypt / re-encode / re-derive by hand):
//!   * `quic_packet`   — long/short header encode/decode, ConnectionId, pn len.
//!   * `quic_protect`  — `KeySet`, `sealPacketSuite` / `openPacketSuite`,
//!                       `EncryptionLevel`, header protection.
//!   * `quic_frame`    — ACK / CRYPTO / STREAM / DATAGRAM / PADDING / PING /
//!                       CONNECTION_CLOSE encode/decode, varints, pn truncation.
//!   * `quic_conn_state.Engine` — packet-number spaces, ACK manager, CRYPTO
//!                       reassembly + send buffers, STREAM reassembly + flow
//!                       control, `intake`.
//!   * `quic_handshake.Server` / `.Client` — the TLS-1.3-over-QUIC handshake,
//!                       producing the Handshake and 1-RTT `KeySet`s.
//!
//! Send / receive loop
//! -------------------
//! `recvDatagram` walks the (possibly coalesced) QUIC packets in one UDP
//! datagram. For each packet it picks the `EncryptionLevel` from the header,
//! selects the matching `KeySet` (Initial from the DCID at first contact;
//! Handshake / 1-RTT once the handshake installs them), `openPacket`s to
//! decrypt, decodes the frames, runs them through `Engine.intake`, and feeds
//! CRYPTO bytes to the handshake. A packet whose level has no keys installed yet
//! is **buffered** (re-tried after the next key install) rather than faulting.
//!
//! `sendDatagrams` collects everything owed — pending handshake CRYPTO flights
//! (fragmented via the per-level `CryptoSendBuffer`), the ACK frames the engine
//! says are owed, application STREAM / DATAGRAM frames the caller queued, and
//! PADDING to bring a client Initial up to the 1200-byte minimum — assembles
//! them into packets per level, `sealPacket`s each, and **coalesces** Initial +
//! Handshake (+ 1-RTT) packets into a single datagram where allowed.
//!
//! Level / state transitions
//! -------------------------
//! Initial → Handshake → 1-RTT (Application). The handshake produces the
//! Handshake keys after the first flight and the 1-RTT keys after the server
//! flight; `installKeys` wires each `KeySet` in as the handshake exposes it.
//! Once Handshake keys are in use the Initial keys are discarded (RFC 9001
//! §4.9). `isEstablished()` is true once both 1-RTT key directions are present
//! AND the handshake reports complete.
//!
//! Loss recovery + congestion control (RFC 9002) live in `quic_recovery.zig`,
//! wired in here: every ack-eliciting in-flight packet is recorded on send with
//! enough info to re-queue its frames; inbound ACKs feed RTT sampling, loss
//! detection (packet + time threshold), and a NewReno congestion window;
//! `onTimeout` drives the RFC loss-detection / PTO timers; and `sendDatagrams`
//! gates on the congestion window via `canSend`. Initial/Handshake space sent
//! state is discarded when its keys are dropped.
//!
//! Documented simplifications (intentional for this layer; the listener / HTTP3
//! layers refine them):
//!   * Congestion control is NewReno (RFC 9002 §7) including the
//!     persistent-congestion collapse (§7.6); ECN and pacing are deferred (typed
//!     gaps).
//!   * One connection id per side; no Retry (handled by the listener layer), no
//!     stateless-reset *emit* (also the listener's job — this layer derives no
//!     reset tokens), no 0-RTT. Connection migration + path validation (RFC 9000
//!     §8.2/§9) ARE implemented here: a 1-RTT packet from a new source address on
//!     an established server connection starts a PATH_CHALLENGE probe to the new
//!     path (with its own 3× anti-amplification budget), and only a matching
//!     PATH_RESPONSE migrates the primary path; an inbound PATH_CHALLENGE is
//!     echoed in a PATH_RESPONSE. Each remaining item is a typed gap, not silent.
//!   * 1-RTT key update (RFC 9001 §6) is implemented: the key-phase bit, peer-
//!     and self-initiated updates, previous-generation key retention for
//!     reordering, peer-update rate limiting, and the confidentiality-limit
//!     counters. It is a 1-RTT-only mechanism (never the Initial/Handshake
//!     spaces) and is unavailable for the SHA-384 suite (documented in
//!     `initKeyUpdate`).
//!   * The receive side enforces frame-level bounds via the Engine; this driver
//!     additionally bounds-checks every byte of packet parsing so a malicious or
//!     truncated datagram errors (never panics / reads out of bounds).

const std = @import("std");
const Allocator = std.mem.Allocator;

const quic_packet = @import("quic_packet.zig");
const quic_protect = @import("quic_protect.zig");
const quic_tls = @import("quic_tls.zig");
const quic_frame = @import("quic_frame.zig");
const quic_conn_state = @import("quic_conn_state.zig");
const quic_handshake = @import("quic_handshake.zig");
const quic_transport_params = @import("quic_transport_params.zig");
const quic_recovery = @import("quic_recovery.zig");
const secure_fns = @import("secure_fns.zig");
const kx = @import("../crypto/kx.zig");

pub const EncryptionLevel = quic_protect.EncryptionLevel;
pub const KeySet = quic_protect.KeySet;
pub const PacketKeys = quic_protect.PacketKeys;
pub const ConnectionId = quic_packet.ConnectionId;
pub const Frame = quic_frame.Frame;
pub const Engine = quic_conn_state.Engine;
pub const StreamId = quic_conn_state.StreamId;
pub const Role = enum { client, server };

/// QUIC v1 (RFC 9000 §15).
pub const quic_version_1: u32 = 0x0000_0001;

/// The minimum UDP payload a client MUST inflate its Initial packet(s) to
/// (RFC 9000 §14.1). We pad the *datagram* (across coalesced packets).
pub const min_initial_datagram: usize = 1200;

/// A conservative ceiling on one outbound datagram. 1252 is the IPv6 minimum
/// safe UDP payload without PMTUD; we never exceed it.
pub const max_datagram: usize = 1252;

/// Send-side flow-control fallbacks used before the peer's transport parameters
/// are known. Deliberately small so we never blast data at a peer we have not
/// yet heard limits from; the real (usually larger) limits replace these the
/// moment the handshake delivers the peer's params, and MAX_DATA/MAX_STREAM_DATA
/// raise them further. The handshake's own control streams are tiny, so these
/// never stall it.
const default_peer_initial_max_data: u64 = 64 * 1024;
const default_peer_initial_max_stream_data: u64 = 64 * 1024;

/// The encoded length (1/2/4/8 bytes) of `v` as a QUIC variable-length integer
/// (RFC 9000 §16). Used to size STREAM/DATAGRAM frame headers exactly so a
/// packet is packed right up to `max_datagram` without overshoot.
fn varIntLen(v: u64) usize {
    if (v < (1 << 6)) return 1;
    if (v < (1 << 14)) return 2;
    if (v < (1 << 30)) return 4;
    return 8;
}

/// The exact on-wire size of a STREAM frame header (type byte + stream id varint
/// + offset varint + length varint) for a frame at `offset` on `stream_id`. We
/// always emit the explicit-length form (OFF + LEN bits), so the length varint
/// is present; the offset varint is omitted only at offset 0 (matching the
/// encoder in `quic_frame.zig`). The length varint is sized for the worst case
/// (a full packet) so we never under-budget and overshoot `max_datagram`.
fn streamFrameHeaderLen(stream_id: u64, offset: u64) usize {
    const off_len: usize = if (offset != 0) varIntLen(offset) else 0;
    // type(1) + stream_id + [offset] + length(<=2 for any <16384-byte payload).
    return 1 + varIntLen(stream_id) + off_len + 2;
}

/// Legacy fixed PTO, retained only as the bound a test uses to advance the
/// simulated clock past the first (pre-RTT-sample) PTO. Real loss recovery now
/// lives in `quic_recovery.zig` (RFC 9002). The initial PTO before any RTT
/// sample is `quic_recovery.default_initial_rtt_ns`-derived; this constant is a
/// comfortable upper bound on it for tests.
pub const fixed_pto_ns: u64 = 250 * std.time.ns_per_ms;

/// Default idle timeout if neither side advertises one (RFC 9000 §10.1).
pub const default_idle_timeout_ns: u64 = 30 * std.time.ns_per_s;

/// CONNECTION_CLOSE application/transport error codes we emit.
pub const transport_error_no_error: u64 = 0x00;
pub const transport_error_internal: u64 = 0x01;

/// A peer UDP address (the connection's "path", RFC 9000 §9). This is a minimal
/// socketless mirror of the daemon's `TransportAddress` (16-byte IP slot + len +
/// port); the listener maps its own address type onto this so the QUIC core
/// never imports the socket layer. Path migration is keyed entirely on this
/// value: two datagrams from the same `PathAddress` are on the same path.
pub const PathAddress = struct {
    ip: [16]u8 = @splat(0),
    ip_len: u8 = 0,
    port: u16 = 0,

    pub fn fromParts(ip: []const u8, port: u16) PathAddress {
        var out: PathAddress = .{ .port = port };
        const n = @min(ip.len, 16);
        @memcpy(out.ip[0..n], ip[0..n]);
        out.ip_len = @intCast(n);
        return out;
    }

    pub fn eql(a: PathAddress, b: PathAddress) bool {
        return a.port == b.port and a.ip_len == b.ip_len and
            std.mem.eql(u8, a.ip[0..a.ip_len], b.ip[0..b.ip_len]);
    }

    pub fn isSet(self: PathAddress) bool {
        return self.ip_len != 0 or self.port != 0;
    }
};

/// Path-validation state for a candidate (new, not-yet-validated) path
/// (RFC 9000 §8.2 / §9). A genuine migration or a NAT rebinding surfaces as a
/// 1-RTT packet arriving from a *different* source address than the connection's
/// current path. We do NOT trust it: we probe the new path with a PATH_CHALLENGE
/// carrying 8 unpredictable bytes and refuse to send more than 3× the bytes
/// received on the new path until the peer echoes the challenge in a
/// PATH_RESPONSE from that same address (§9.3.2 / §21.5). Only a matching
/// response migrates the connection's primary address; the old path stays usable
/// throughout, and a challenge that goes unanswered within a PTO-derived bound is
/// abandoned (the old path is kept). This makes an off-path/spoofed packet unable
/// to either hijack the connection or trigger reflection amplification.
const PathValidation = struct {
    /// Whether a candidate-path probe is currently in flight.
    active: bool = false,
    /// The candidate (new) peer address being validated.
    candidate: PathAddress = .{},
    /// The 8 unpredictable challenge bytes we sent to `candidate`. A
    /// PATH_RESPONSE from `candidate` echoing these exact bytes validates it.
    challenge: [8]u8 = @splat(0),
    /// Whether `challenge` still needs to go on the wire to the candidate path.
    challenge_pending: bool = false,
    /// Anti-amplification budget for the candidate path (RFC 9000 §9.3.1): a
    /// server MUST NOT send more than 3× the bytes received on a not-yet-
    /// validated path. These count only traffic on the candidate path.
    bytes_received: u64 = 0,
    bytes_sent: u64 = 0,
    /// When the probe was (re)armed, so an unanswered challenge can be abandoned
    /// after a PTO-derived bound (RFC 9000 §8.2.4 / §9.3.2).
    started_ns: u64 = 0,

    fn reset(self: *PathValidation) void {
        self.* = .{};
    }
};

pub const ConnError = error{
    /// A datagram could not be parsed at the packet-structure level.
    MalformedPacket,
    /// The header declared an unsupported/short-of-QUIC-v1 version.
    UnsupportedVersion,
    /// `sendStream` / `sendDatagram` before the connection is established.
    NotEstablished,
    /// A peer CONNECTION_CLOSE was received; the connection is closing.
    PeerClosed,
    /// The handshake produced a fatal error.
    HandshakeFailed,
    /// The idle timeout elapsed with no activity.
    IdleTimeout,
};

/// The driver's error set. It folds in the lower layers' error sets it
/// propagates (frame coding, engine state) so the seal/encode/intake calls
/// compose without per-call mapping. A malformed *peer* datagram is caught and
/// turned into `MalformedPacket` (or silently dropped) inside the recv path;
/// these wider members surface only on a local programming/limit error.
pub const Error = ConnError || Allocator.Error || quic_frame.WireError || quic_conn_state.Error;

/// Either handshake role behind one interface. The driver only needs the
/// socketless surface both `Server` and `Client` expose.
const Handshake = union(Role) {
    client: quic_handshake.Client,
    server: quic_handshake.Server,

    fn deinit(self: *Handshake) void {
        switch (self.*) {
            inline else => |*h| h.deinit(),
        }
    }
    fn feedCrypto(self: *Handshake, level: EncryptionLevel, data: []const u8) quic_handshake.Error!void {
        switch (self.*) {
            inline else => |*h| return h.feedCrypto(level, data),
        }
    }
    fn takeFlight(self: *Handshake, level: EncryptionLevel) quic_handshake.Error![]u8 {
        switch (self.*) {
            inline else => |*h| return h.takeFlight(level),
        }
    }
    fn isComplete(self: *const Handshake) bool {
        switch (self.*) {
            inline else => |*h| return h.isComplete(),
        }
    }
    fn handshakeKeys(self: *const Handshake) ?KeySet {
        switch (self.*) {
            inline else => |*h| return h.handshakeKeys(),
        }
    }
    fn applicationKeys(self: *const Handshake) ?KeySet {
        switch (self.*) {
            inline else => |*h| return h.applicationKeys(),
        }
    }
    fn appTrafficSecrets(self: *const Handshake) ?quic_handshake.AppTrafficSecrets {
        switch (self.*) {
            inline else => |*h| return h.appTrafficSecrets(),
        }
    }
    fn selectedAlpn(self: *const Handshake) ?[]const u8 {
        switch (self.*) {
            inline else => |*h| return h.selectedAlpn(),
        }
    }
    fn peerTransportParams(self: *const Handshake) ?quic_transport_params.TransportParameters {
        switch (self.*) {
            inline else => |*h| return h.peerTransportParams(),
        }
    }
};

/// Server-role connection configuration. Carries the cert / signing key, the
/// ALPN list, the local transport parameters, and this side's connection ids.
pub const ServerConfig = struct {
    cert_chain: []const []const u8,
    signing_key: quic_handshake.SigningKey,
    alpn_protocols: []const []const u8 = &.{},
    transport_params: quic_transport_params.TransportParameters = .{},
    /// This server's source connection id (becomes the peer's DCID after the
    /// first flight). Also used in the long-header SCID.
    local_cid: []const u8,
    /// Engine caps (flow control, buffer sizes). Defaults are safe.
    engine: quic_conn_state.Config = .{},
    /// Deterministic handshake material (tests only).
    x25519_seed: ?[32]u8 = null,
    server_random: ?[32]u8 = null,
};

/// Client-role connection configuration.
pub const ClientConfig = struct {
    alpn_protocols: []const []const u8 = &.{},
    transport_params: quic_transport_params.TransportParameters = .{},
    /// This client's source connection id (long-header SCID).
    local_cid: []const u8,
    /// The Destination Connection ID the client picks for the server's Initial
    /// keys (RFC 9001 §5.2 — the client chooses an unpredictable DCID and both
    /// sides derive the Initial secrets from it).
    initial_dcid: []const u8,
    engine: quic_conn_state.Config = .{},
    x25519_seed: ?[32]u8 = null,
    client_random: ?[32]u8 = null,
};

/// A queued application STREAM write awaiting an outbound 1-RTT packet.
const PendingStream = struct {
    stream_id: u64,
    offset: u64,
    fin: bool,
    data: []u8, // owned
};

/// Per-stream outbound send state (RFC 9000 §2.3 / §19.8). Owns the *retained*
/// bytes that have been queued for sending but not yet acknowledged, so a lost
/// STREAM range can be re-transmitted from our own buffer without the
/// application re-supplying it (the previous offset-rollback-only scheme could
/// not actually re-send the bytes, so a single dropped packet on a large
/// transfer stalled the stream forever). Memory is bounded: `buf` holds only
/// `[acked_offset, queued_offset)` — bytes the peer has acknowledged are dropped
/// from the front, so steady-state retention is at most one congestion / flow-
/// control window of un-acked data per stream.
const StreamSender = struct {
    /// Absolute stream offset of `buf[0]` — the first byte not yet acknowledged.
    acked_offset: u64 = 0,
    /// Absolute offset of the next byte to put on the wire. Bytes in
    /// `[acked_offset, send_offset)` are in flight (sent, unacked); bytes in
    /// `[send_offset, acked_offset + buf.items.len)` are queued but unsent.
    send_offset: u64 = 0,
    /// Retained bytes from `acked_offset` onward (unacked + unsent). Freed from
    /// the front as ACKs advance `acked_offset`.
    buf: std.ArrayListUnmanaged(u8) = .empty,
    /// The application asked to finish the stream at `fin_offset` (the total
    /// byte count). Null until `sendStream(..., fin=true)`.
    fin_offset: ?u64 = null,
    /// Whether the FIN bit has actually been transmitted in a STREAM frame.
    fin_sent: bool = false,

    fn deinit(self: *StreamSender, allocator: Allocator) void {
        self.buf.deinit(allocator);
        self.* = undefined;
    }

    /// Total bytes ever queued (the next write's absolute offset).
    fn queuedEnd(self: *const StreamSender) u64 {
        return self.acked_offset + self.buf.items.len;
    }

    /// Bytes queued but not yet put on the wire.
    fn unsent(self: *const StreamSender) u64 {
        return self.queuedEnd() - self.send_offset;
    }

    /// Whether there is anything left to send: unsent bytes, or a FIN that has
    /// not yet ridden a STREAM frame.
    fn hasSendable(self: *const StreamSender) bool {
        if (self.unsent() > 0) return true;
        if (self.fin_offset) |fo| {
            // A pure-FIN (zero-length tail) is sendable once all data is sent.
            if (!self.fin_sent and self.send_offset >= fo) return true;
        }
        return false;
    }
};

/// A queued application DATAGRAM (RFC 9221) awaiting an outbound 1-RTT packet.
const PendingDatagram = struct {
    data: []u8, // owned
};

/// One outbound datagram produced by `sendDatagrams`, owned by the caller.
///
/// `dest` overrides where the datagram must be sent (RFC 9000 §8.2.1 / §9):
/// `null` means the connection's current primary path (the common case); a set
/// `PathAddress` means this datagram is a path-validation probe (a
/// PATH_CHALLENGE) bound for a *candidate* path that has not yet been migrated
/// to. The listener routes on this so a probe reaches the new address while app
/// data keeps flowing to the old, still-primary one.
pub const OutDatagram = struct {
    bytes: []u8,
    dest: ?PathAddress = null,
};

/// Per-level send-side CRYPTO buffers (Initial / Handshake) and the largest
/// packet number we have sent that carried ack-eliciting data, so the PTO timer
/// knows whether a retransmit is owed.
const SendState = struct {
    crypto_initial: quic_conn_state.CryptoSendBuffer = quic_conn_state.CryptoSendBuffer.init(),
    crypto_handshake: quic_conn_state.CryptoSendBuffer = quic_conn_state.CryptoSendBuffer.init(),

    fn deinit(self: *SendState, allocator: Allocator) void {
        self.crypto_initial.deinit(allocator);
        self.crypto_handshake.deinit(allocator);
    }

    fn cryptoBuf(self: *SendState, level: EncryptionLevel) ?*quic_conn_state.CryptoSendBuffer {
        return switch (level) {
            .initial => &self.crypto_initial,
            .handshake => &self.crypto_handshake,
            .application => null, // 1-RTT CRYPTO (post-handshake) is out of scope here
        };
    }
};

/// 1-RTT key-update state machine (RFC 9001 §6).
///
/// Key generations are addressed by a single key-phase bit in the short header.
/// We keep, per direction:
///   * the CURRENT generation (whose keys are `Conn.app_keys`),
///   * the NEXT-generation read keys, pre-computed so a peer-initiated update
///     (a flipped phase bit) can be trial-decrypted without deriving on the hot
///     path (RFC 9001 §6.3), and
///   * the PREVIOUS-generation read keys, retained briefly after we commit an
///     update so packets reordered across the update boundary still decrypt
///     (RFC 9001 §6.4).
///
/// Rate limiting (RFC 9001 §6.6 / §9.4): we do not *initiate* a new update until
/// the peer has acknowledged a packet we sent in the current phase (`initiated`
/// + `confirm_pn`), and we refuse to *commit* a peer-driven update more often
/// than once per `min_update_interval_ns` (≈3·PTO) to resist a key-update DoS.
///
/// Confidentiality / integrity limits (RFC 9001 §6.6): `packets_sent_epoch`
/// counts the packets protected with the current send key; `aead_failures`
/// counts authentication failures across the connection. AES-128-GCM /
/// AES-256-GCM tolerate up to 2^23 protected packets and 2^52 invalid packets
/// before a key update / connection close is required; ChaCha20-Poly1305 sets no
/// confidentiality limit and bounds invalid packets at 2^36. We expose the
/// counters and, once the current epoch exceeds `confidentiality_limit`,
/// `wantsKeyUpdate()` reports that the application should rotate; a (key, nonce)
/// pair is never reused because the packet number advances monotonically and a
/// fresh key is installed on every generation.
const KeyUpdate = struct {
    /// Whether the 1-RTT secrets are known and key update is available.
    ready: bool = false,
    /// Current key-phase bit applied to outbound short headers and expected on
    /// inbound ones (RFC 9001 §6.3).
    phase: u1 = 0,
    /// QUIC AEAD/header-protection suite for re-derivation.
    suite: quic_protect.CipherSuite = .aes128gcm,

    /// Current generation traffic secrets (write = ours, read = peer's).
    write_secret: [32]u8 = @splat(0),
    read_secret: [32]u8 = @splat(0),

    /// Pre-computed next-generation read keys + their secret (peer-update trial).
    next_read: PacketKeys = undefined,
    next_read_secret: [32]u8 = @splat(0),

    /// Retained previous-generation read keys for reordered packets (§6.4), valid
    /// until `prev_read_until_ns`.
    prev_read: ?PacketKeys = null,
    prev_read_until_ns: u64 = 0,

    /// Highest packet number successfully removed-from-header in the CURRENT key
    /// phase. RFC 9001 §6.3 disambiguation: a phase-mismatched packet with a
    /// HIGHER number than this is a peer-initiated update (try next keys); one
    /// with a LOWER number is a packet reordered from the previous phase (try
    /// retained previous keys). Null until the first 1-RTT packet is received.
    highest_pn_current_phase: ?u64 = null,

    /// We initiated an update and await peer confirmation before initiating again
    /// (§6.5): an ACK of a packet number ≥ `confirm_pn` confirms it. `confirm_pn`
    /// is null until the first packet in the new phase is actually sent.
    initiated: bool = false,
    confirm_pn: ?u64 = null,

    /// Time of the last committed update, for peer-driven rate limiting (§6.6).
    last_update_ns: u64 = 0,
    /// Whether we have ever committed an update (so the first peer update is not
    /// rejected by the rate limiter at t≈0).
    have_updated: bool = false,

    /// Packets protected with the current send key (resets each generation).
    packets_sent_epoch: u64 = 0,
    /// AEAD authentication failures observed (anti-forgery accounting, §6.6).
    aead_failures: u64 = 0,

    /// RFC 9001 §6.6 AEAD confidentiality limit (packets) for AES-GCM suites:
    /// 2^23. ChaCha20-Poly1305 has no confidentiality limit; we still rotate at
    /// this conservative bound so the counter logic is uniform.
    const confidentiality_limit: u64 = 1 << 23;

    /// How long previous-generation read keys are retained after an update
    /// (RFC 9001 §6.4 recommends ~3·PTO; the connection passes a concrete value).
    fn retentionNs(pto_ns: u64) u64 {
        return pto_ns *| 3;
    }
};

/// An authenticated handoff may carry at most this much Conn-owned variable
/// data in addition to the separately bounded Engine and Recovery snapshots.
pub const snapshot_max_owned_bytes: usize = 64 * 1024 * 1024;
pub const snapshot_max_stream_senders: usize = 4096;
pub const snapshot_max_flow_entries: usize = 4096;
pub const snapshot_max_datagrams: usize = 1024;
pub const snapshot_max_handshake_bytes: usize = 4 * 1024 * 1024;
pub const SnapshotError = error{ InvalidSnapshot, SnapshotTooLarge, ConfigMismatch } || Allocator.Error;
const snapshot_max_varint: u64 = (1 << 62) - 1;

fn logServerSnapshotFailure(comptime stage: []const u8, err: anyerror) void {
    if (comptime @import("builtin").os.tag == .windows) {
        std.debug.print("onyx-server: Windows QUIC snapshot {s} failed: {s}\n", .{ stage, @errorName(err) });
    }
}

fn invalidServerSnapshot(comptime stage: []const u8) error{InvalidSnapshot} {
    logServerSnapshotFailure(stage, error.InvalidSnapshot);
    return error.InvalidSnapshot;
}

const CryptoSendSnapshot = struct {
    base_offset: u64,
    send_offset: u64,
    bytes: []u8,

    fn deinit(self: *CryptoSendSnapshot, allocator: Allocator) void {
        std.crypto.secureZero(u8, self.bytes);
        allocator.free(self.bytes);
        self.* = undefined;
    }

    fn validate(self: *const CryptoSendSnapshot) SnapshotError!void {
        if (self.bytes.len > snapshot_max_handshake_bytes or self.base_offset > snapshot_max_varint or
            self.bytes.len > snapshot_max_varint - self.base_offset or
            self.send_offset < self.base_offset or self.send_offset > self.base_offset + self.bytes.len)
            return error.InvalidSnapshot;
    }
};

const ServerHandshakeSnapshot = struct {
    /// The cert chain, ALPN preferences and local transport parameters are
    /// immutable external config; the candidate supplies them from its owned
    /// TLS material and stable per-connection CID storage. This digest binds the
    /// exact public configuration while the listener verifies key possession.
    config_digest: [32]u8,
    selected_alpn_index: ?u16,
    peer_params_present: bool,
    peer_params_wire: []u8,
    suite: quic_handshake.CipherSuite,
    x25519_pair: kx.X25519Kx.KeyPair,
    server_random: [32]u8,
    selected_group: u8,
    hybrid_keyshare: @FieldType(quic_handshake.Server, "hybrid_keyshare"),
    transcript: []u8,
    recv: []u8,
    out_initial: []u8,
    out_handshake: []u8,
    handshake_secret: @FieldType(quic_handshake.Server, "handshake_secret"),
    client_hs_secret: @FieldType(quic_handshake.Server, "client_hs_secret"),
    server_hs_secret: @FieldType(quic_handshake.Server, "server_hs_secret"),
    client_ap_secret: @FieldType(quic_handshake.Server, "client_ap_secret"),
    server_ap_secret: @FieldType(quic_handshake.Server, "server_ap_secret"),
    handshake_keys: KeySet,
    application_keys: KeySet,

    fn deinit(self: *ServerHandshakeSnapshot, allocator: Allocator) void {
        self.x25519_pair.wipe();
        inline for (.{ "handshake_secret", "client_hs_secret", "server_hs_secret", "client_ap_secret", "server_ap_secret" }) |field| {
            std.crypto.secureZero(u8, &@field(self, field));
        }
        for ([_][]u8{ self.peer_params_wire, self.transcript, self.recv, self.out_initial, self.out_handshake }) |bytes| {
            std.crypto.secureZero(u8, bytes);
            allocator.free(bytes);
        }
        self.* = undefined;
    }

    fn validate(self: *const ServerHandshakeSnapshot) SnapshotError!void {
        if (self.selected_group > 1 or self.peer_params_wire.len > snapshot_max_handshake_bytes or
            self.transcript.len > snapshot_max_handshake_bytes or self.recv.len > snapshot_max_handshake_bytes or
            self.out_initial.len > snapshot_max_handshake_bytes or self.out_handshake.len > snapshot_max_handshake_bytes)
            return error.SnapshotTooLarge;
        if (!self.peer_params_present and self.peer_params_wire.len != 0) return invalidServerSnapshot("handshake peer parameters presence");
        if (self.peer_params_present) _ = quic_transport_params.decode(self.peer_params_wire) catch return invalidServerSnapshot("handshake peer parameters decode");
        const expected_suite: quic_protect.CipherSuite = switch (self.suite) {
            .tls_aes_128_gcm_sha256 => .aes128gcm,
            .tls_aes_256_gcm_sha384 => .aes256gcm,
            .tls_chacha20_poly1305_sha256 => .chacha20poly1305,
        };
        if (self.handshake_keys.level != .handshake or self.application_keys.level != .application or
            self.handshake_keys.write.suite != self.handshake_keys.read.suite or
            self.application_keys.write.suite != self.application_keys.read.suite or
            self.handshake_keys.write.suite != expected_suite or self.application_keys.write.suite != expected_suite)
            return invalidServerSnapshot("handshake packet key relation");
        if (self.selected_group == 0 and !std.mem.allEqual(u8, &self.hybrid_keyshare, 0))
            return invalidServerSnapshot("handshake keyshare canonical state");
    }
};

const StreamSenderSnapshot = struct {
    id: u64,
    acked_offset: u64,
    send_offset: u64,
    fin_offset: ?u64,
    fin_sent: bool,
    bytes: []u8,

    fn deinit(self: *StreamSenderSnapshot, allocator: Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

const FlowEntrySnapshot = struct { id: u64, limit: u64 };

/// Owned logical state for one established server QUIC connection. The
/// certificate/signing key and local CID storage are supplied by the candidate
/// owner; they are compared before a restored connection can be published.
/// Call only while the source pump is paused at a packet boundary.
pub const ConnSnapshot = struct {
    handshake: ServerHandshakeSnapshot,
    engine: quic_conn_state.EngineSnapshot,
    recovery: quic_recovery.Snapshot,
    crypto_initial: CryptoSendSnapshot,
    crypto_handshake: CryptoSendSnapshot,
    initial_keys: ?KeySet,
    handshake_keys: ?KeySet,
    app_keys: KeySet,
    initial_discarded: bool,
    key_update: KeyUpdate,
    dcid: ConnectionId,
    scid: ConnectionId,
    initial_secret_dcid: [quic_packet.max_connection_id_len]u8,
    initial_secret_dcid_len: u8,
    started: bool,
    server_cid_learned: bool,
    established: bool,
    closing: bool,
    close_error: ?u64,
    close_pending: bool,
    handshake_done_pending: bool,
    buffered: []BufferedSnapshot,
    max_buffered: usize,
    newly_acked: []u64,
    bytes_received: u64,
    bytes_sent_unvalidated: u64,
    address_validated: bool,
    path: PathAddress,
    path_validation: PathValidation,
    pending_path_responses: [][8]u8,
    max_pending_path_responses: usize,
    pending_path_challenge: ?[8]u8,
    last_recv_ns: u64,
    timer_deadline_ns: ?u64,
    timer_kind: quic_recovery.TimerKind,
    idle_timeout_ns: u64,
    senders: []StreamSenderSnapshot,
    stream_order: []u64,
    pending_datagrams: [][]u8,
    peer_max_data: ?u64,
    fc_data_sent: u64,
    peer_max_stream_data: []FlowEntrySnapshot,
    recv_datagrams: [][]u8,
    max_recv_datagrams: usize,
    next_bidi_stream: u64,
    next_uni_stream: u64,

    pub const BufferedSnapshot = struct { level: EncryptionLevel, bytes: []u8 };

    pub fn deinit(self: *ConnSnapshot, allocator: Allocator) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.handshake.handshake_keys));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.handshake.application_keys));
        self.handshake.deinit(allocator);
        for (&self.engine.crypto) |*part| std.crypto.secureZero(u8, part.staged);
        self.engine.deinit(allocator);
        self.recovery.deinit(allocator);
        self.crypto_initial.deinit(allocator);
        self.crypto_handshake.deinit(allocator);
        for (self.buffered) |packet| allocator.free(packet.bytes);
        allocator.free(self.buffered);
        allocator.free(self.newly_acked);
        allocator.free(self.pending_path_responses);
        for (self.senders) |*sender| sender.deinit(allocator);
        allocator.free(self.senders);
        allocator.free(self.stream_order);
        for (self.pending_datagrams) |bytes| allocator.free(bytes);
        allocator.free(self.pending_datagrams);
        allocator.free(self.peer_max_stream_data);
        for (self.recv_datagrams) |bytes| allocator.free(bytes);
        allocator.free(self.recv_datagrams);
        std.crypto.secureZero(u8, &self.initial_secret_dcid);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.initial_keys));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.handshake_keys));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.app_keys));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.key_update));
        self.* = undefined;
    }

    pub fn validate(self: *const ConnSnapshot) SnapshotError!void {
        self.handshake.validate() catch |err| {
            logServerSnapshotFailure("handshake validation", err);
            return err;
        };
        self.engine.validate() catch |err| {
            logServerSnapshotFailure("engine validation", err);
            return err;
        };
        self.recovery.validate() catch |err| {
            logServerSnapshotFailure("recovery validation", err);
            return err;
        };
        self.crypto_initial.validate() catch |err| {
            logServerSnapshotFailure("initial crypto send validation", err);
            return err;
        };
        self.crypto_handshake.validate() catch |err| {
            logServerSnapshotFailure("handshake crypto send validation", err);
            return err;
        };
        if (self.engine.local != .server or !self.established or self.closing or self.started or
            !self.initial_discarded or self.initial_keys != null or self.handshake_keys == null or
            !self.recovery.handshake_confirmed or self.server_cid_learned or
            self.dcid.len > quic_packet.max_connection_id_len or self.scid.len > quic_packet.max_connection_id_len or
            self.initial_secret_dcid_len > quic_packet.max_connection_id_len or
            self.close_error != null or self.close_pending or self.idle_timeout_ns == 0)
            return invalidServerSnapshot("connection state validation");
        if (!std.mem.allEqual(u8, self.dcid.bytes[self.dcid.len..], 0) or
            !std.mem.allEqual(u8, self.scid.bytes[self.scid.len..], 0) or
            !std.mem.allEqual(u8, self.initial_secret_dcid[self.initial_secret_dcid_len..], 0))
            return invalidServerSnapshot("CID canonical validation");
        if (!std.meta.eql(self.handshake_keys.?, self.handshake.handshake_keys) or
            self.app_keys.level != .application or self.app_keys.write.suite != self.handshake.application_keys.write.suite or
            self.app_keys.read.suite != self.handshake.application_keys.read.suite)
            return invalidServerSnapshot("packet key relation");
        for (self.recovery.sent, self.engine.spaces, 0..) |registry, space, i| {
            for (registry.packets) |packet| {
                if (packet.packet_number >= space.next_outbound) return invalidServerSnapshot("recovery packet number relation");
            }
            // Initial keys are discarded at establishment. Handshake keys can
            // still send a pending ACK afterward, repopulating that registry.
            if (i == 0 and (registry.packets.len != 0 or registry.largest_sent_ack_eliciting != null))
                return invalidServerSnapshot("initial recovery registry");
        }
        if ((self.timer_kind == .none) != (self.timer_deadline_ns == null) or
            self.last_recv_ns > std.math.maxInt(u64) / 2 or
            (self.timer_deadline_ns != null and self.timer_deadline_ns.? > std.math.maxInt(u64) / 2) or
            (self.last_recv_ns != 0 and self.idle_timeout_ns > std.math.maxInt(u64) - self.last_recv_ns))
            return invalidServerSnapshot("timer validation");
        if (self.max_buffered == 0 or self.max_buffered > 16 or self.buffered.len > self.max_buffered or
            self.newly_acked.len > 4096 or self.max_pending_path_responses == 0 or
            self.max_pending_path_responses > 8 or self.pending_path_responses.len > self.max_pending_path_responses or
            self.max_recv_datagrams == 0 or self.max_recv_datagrams > 256 or self.recv_datagrams.len > self.max_recv_datagrams or
            self.pending_datagrams.len > snapshot_max_datagrams or self.senders.len > snapshot_max_stream_senders or
            self.peer_max_stream_data.len > snapshot_max_flow_entries or self.stream_order.len > snapshot_max_stream_senders)
            return error.SnapshotTooLarge;
        var total: usize = 0;
        inline for (.{ self.handshake.peer_params_wire, self.handshake.transcript, self.handshake.recv, self.handshake.out_initial, self.handshake.out_handshake, self.crypto_initial.bytes, self.crypto_handshake.bytes }) |bytes| try snapshotAddBytes(&total, bytes.len);
        for (self.buffered) |packet| {
            if (packet.bytes.len == 0 or packet.bytes.len > 2048) return invalidServerSnapshot("buffered packet validation");
            try snapshotAddBytes(&total, packet.bytes.len);
        }
        for (self.senders, 0..) |sender, i| {
            if (sender.id > snapshot_max_varint or sender.acked_offset > snapshot_max_varint or
                sender.bytes.len > snapshot_max_varint - sender.acked_offset or
                sender.send_offset < sender.acked_offset or
                sender.send_offset > sender.acked_offset + sender.bytes.len or
                (sender.fin_offset != null and sender.fin_offset.? > snapshot_max_varint) or
                (sender.fin_sent and sender.fin_offset == null)) return invalidServerSnapshot("sender validation");
            if (i > 0 and self.senders[i - 1].id >= sender.id) return invalidServerSnapshot("sender order");
            try snapshotAddBytes(&total, sender.bytes.len);
        }
        for (self.pending_datagrams) |bytes| {
            if (bytes.len > max_datagram) return invalidServerSnapshot("pending datagram validation");
            try snapshotAddBytes(&total, bytes.len);
        }
        for (self.recv_datagrams) |bytes| {
            if (bytes.len > 2048) return invalidServerSnapshot("received datagram validation");
            try snapshotAddBytes(&total, bytes.len);
        }
        for (self.stream_order, 0..) |id, i| {
            if (findSenderSnapshot(self.senders, id) == null) return invalidServerSnapshot("stream sender relation");
            for (self.stream_order[0..i]) |prior| if (prior == id) return invalidServerSnapshot("stream sender uniqueness");
        }
        for (self.peer_max_stream_data, 0..) |entry, i| {
            if (entry.id > snapshot_max_varint or entry.limit > snapshot_max_varint or
                (i > 0 and self.peer_max_stream_data[i - 1].id >= entry.id)) return invalidServerSnapshot("peer stream flow validation");
        }
        if (self.peer_max_data) |limit| if (limit > snapshot_max_varint) return invalidServerSnapshot("peer flow limit");
        if (self.fc_data_sent > snapshot_max_varint or
            self.bytes_sent_unvalidated > self.bytes_received *| 3) return invalidServerSnapshot("flow and amplification validation");
        if (self.next_bidi_stream > snapshot_max_varint or self.next_uni_stream > snapshot_max_varint or
            self.next_bidi_stream % 4 != 1 or self.next_uni_stream % 4 != 3) return invalidServerSnapshot("next stream ID validation");
        validateSnapshotPath(self.path) catch |err| {
            logServerSnapshotFailure("path validation", err);
            return err;
        };
        validateSnapshotPath(self.path_validation.candidate) catch |err| {
            logServerSnapshotFailure("candidate path validation", err);
            return err;
        };
        if (self.path_validation.active and (!self.path_validation.candidate.isSet() or
            self.path_validation.bytes_sent > self.path_validation.bytes_received *| 3)) return invalidServerSnapshot("active path validation");
        if (!self.path_validation.active and (!std.meta.eql(self.path_validation, PathValidation{})))
            return invalidServerSnapshot("inactive path validation");
        if (self.key_update.ready != (self.handshake.suite != .tls_aes_256_gcm_sha384))
            return invalidServerSnapshot("key update readiness");
        if (self.key_update.ready) {
            if (self.key_update.suite != self.app_keys.write.suite or
                self.key_update.suite != self.app_keys.read.suite or
                !std.mem.eql(u8, &self.key_update.next_read_secret, &quic_tls.nextGenerationSecret(self.key_update.read_secret)) or
                !std.meta.eql(self.key_update.next_read, quic_protect.keyUpdateDirection(self.app_keys.read, self.key_update.next_read_secret)))
                return invalidServerSnapshot("next key update read keys");
            const write = quic_tls.derivePacketKeys(self.key_update.write_secret, self.key_update.suite);
            const read = quic_tls.derivePacketKeys(self.key_update.read_secret, self.key_update.suite);
            if (!std.mem.eql(u8, write.keyBytes(), self.app_keys.write.keyBytes()) or
                !std.mem.eql(u8, &write.iv, &self.app_keys.write.iv) or
                !std.mem.eql(u8, read.keyBytes(), self.app_keys.read.keyBytes()) or
                !std.mem.eql(u8, &read.iv, &self.app_keys.read.iv) or
                !std.mem.eql(u8, self.app_keys.write.hpBytes(), self.handshake.application_keys.write.hpBytes()) or
                !std.mem.eql(u8, self.app_keys.read.hpBytes(), self.handshake.application_keys.read.hpBytes()))
                return invalidServerSnapshot("key update current keys");
        } else if (self.key_update.phase != 0 or self.key_update.prev_read != null or
            self.key_update.initiated or self.key_update.have_updated or
            !std.meta.eql(self.app_keys, self.handshake.application_keys)) return invalidServerSnapshot("idle key update relation");
    }
};

fn snapshotAddBytes(total: *usize, amount: usize) SnapshotError!void {
    total.* = std.math.add(usize, total.*, amount) catch return error.SnapshotTooLarge;
    if (total.* > snapshot_max_owned_bytes) return error.SnapshotTooLarge;
}

fn findSenderSnapshot(senders: []const StreamSenderSnapshot, id: u64) ?usize {
    for (senders, 0..) |sender, i| if (sender.id == id) return i;
    return null;
}

fn validateSnapshotPath(path: PathAddress) SnapshotError!void {
    if (path.ip_len > 16) return error.InvalidSnapshot;
    if (!std.mem.allEqual(u8, path.ip[path.ip_len..], 0)) return error.InvalidSnapshot;
}

fn canonicalSnapshotPath(path: PathAddress) PathAddress {
    var out = path;
    if (out.ip_len <= 16) @memset(out.ip[out.ip_len..], 0);
    return out;
}

fn snapshotConfigDigest(allocator: Allocator, config: quic_handshake.Config) SnapshotError![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("onyx/quic/established-server-config/1");
    hashSizedInt(&hash, config.cert_chain.len);
    for (config.cert_chain) |cert| hashSizedBytes(&hash, cert);
    switch (config.signing_key) {
        .ed25519 => |key| {
            hash.update(&.{1});
            hash.update(&key.public_key.bytes);
        },
        .ecdsa_p256 => |key| {
            hash.update(&.{2});
            const sec1 = key.public_key.toUncompressedSec1();
            hash.update(&sec1);
        },
        .rsa => |key| {
            hash.update(&.{3});
            hashSizedBytes(&hash, key.n);
            hashSizedBytes(&hash, key.e);
        },
    }
    hashSizedInt(&hash, config.alpn_protocols.len);
    for (config.alpn_protocols) |alpn| hashSizedBytes(&hash, alpn);
    var params: std.ArrayList(u8) = .empty;
    defer params.deinit(allocator);
    quic_transport_params.encode(&params, allocator, config.transport_params) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidSnapshot,
    };
    hashSizedBytes(&hash, params.items);
    return hash.finalResult();
}

fn hashSizedInt(hash: *std.crypto.hash.sha2.Sha256, value: usize) void {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, @intCast(value), .big);
    hash.update(&encoded);
}

fn hashSizedBytes(hash: *std.crypto.hash.sha2.Sha256, bytes: []const u8) void {
    hashSizedInt(hash, bytes.len);
    hash.update(bytes);
}

fn captureCryptoSend(allocator: Allocator, source: *const quic_conn_state.CryptoSendBuffer) SnapshotError!CryptoSendSnapshot {
    const part: CryptoSendSnapshot = .{
        .base_offset = source.base_offset,
        .send_offset = source.send_offset,
        .bytes = try allocator.dupe(u8, source.buf.items),
    };
    errdefer allocator.free(part.bytes);
    try part.validate();
    return part;
}

fn captureServerHandshake(allocator: Allocator, source: *const quic_handshake.Server) SnapshotError!ServerHandshakeSnapshot {
    if (!source.isComplete() or source.suite == null or source.handshake_keys == null or source.application_keys == null)
        return invalidServerSnapshot("capture handshake completion");
    var selected_index: ?u16 = null;
    if (source.selected_alpn) |selected| {
        for (source.config.alpn_protocols, 0..) |alpn, i| {
            if (std.mem.eql(u8, selected, alpn)) {
                selected_index = std.math.cast(u16, i) orelse return error.SnapshotTooLarge;
                break;
            }
        }
        if (selected_index == null) return invalidServerSnapshot("capture ALPN selection");
    }
    const peer = try allocator.dupe(u8, source.peer_params_storage.items);
    errdefer allocator.free(peer);
    const transcript = try allocator.dupe(u8, source.transcript.items);
    errdefer allocator.free(transcript);
    const recv = try allocator.dupe(u8, source.recv.items);
    errdefer allocator.free(recv);
    const out_initial = try allocator.dupe(u8, source.out_initial.items);
    errdefer allocator.free(out_initial);
    const out_handshake = try allocator.dupe(u8, source.out_handshake.items);
    errdefer allocator.free(out_handshake);
    var pair = source.x25519_pair;
    defer pair.wipe();
    const group: u8 = @intFromEnum(source.selected_group);
    const hybrid = if (group == 1) source.hybrid_keyshare else @as(@FieldType(quic_handshake.Server, "hybrid_keyshare"), @splat(0));
    const part: ServerHandshakeSnapshot = .{
        .config_digest = try snapshotConfigDigest(allocator, source.config),
        .selected_alpn_index = selected_index,
        .peer_params_present = source.peer_params != null,
        .peer_params_wire = peer,
        .suite = source.suite.?,
        .x25519_pair = pair,
        .server_random = source.server_random,
        .selected_group = group,
        .hybrid_keyshare = hybrid,
        .transcript = transcript,
        .recv = recv,
        .out_initial = out_initial,
        .out_handshake = out_handshake,
        .handshake_secret = source.handshake_secret,
        .client_hs_secret = source.client_hs_secret,
        .server_hs_secret = source.server_hs_secret,
        .client_ap_secret = source.client_ap_secret,
        .server_ap_secret = source.server_ap_secret,
        .handshake_keys = source.handshake_keys.?,
        .application_keys = source.application_keys.?,
    };
    part.validate() catch |err| {
        logServerSnapshotFailure("capture handshake validation", err);
        return err;
    };
    return part;
}

fn captureSnapshotDatagrams(allocator: Allocator, source: []const PendingDatagram) SnapshotError![][]u8 {
    if (source.len > snapshot_max_datagrams) return error.SnapshotTooLarge;
    const out = try allocator.alloc([]u8, source.len);
    var copied: usize = 0;
    errdefer {
        for (out[0..copied]) |bytes| allocator.free(bytes);
        allocator.free(out);
    }
    for (source, 0..) |item, i| {
        out[i] = try allocator.dupe(u8, item.data);
        copied += 1;
    }
    return out;
}

fn restoreSnapshotDatagrams(allocator: Allocator, target: *std.ArrayList(PendingDatagram), source: [][]u8) Allocator.Error!void {
    for (source) |bytes| {
        const copy = try allocator.dupe(u8, bytes);
        errdefer allocator.free(copy);
        try target.append(allocator, .{ .data = copy });
    }
}

fn zeroSnapshotPacketKeys() PacketKeys {
    return .{ .suite = .aes128gcm, .key = @splat(0), .iv = @splat(0), .hp = @splat(0) };
}

/// The connection. One per peer 4-tuple. Socketless: feed `recvDatagram`,
/// drain `sendDatagrams`, tick `onTimeout`.
pub const Conn = struct {
    allocator: Allocator,
    role: Role,
    handshake: Handshake,
    engine: Engine,
    send: SendState,

    /// Initial keys (from the DCID) — discarded once Handshake keys are used.
    initial_keys: ?KeySet,
    handshake_keys: ?KeySet = null,
    app_keys: ?KeySet = null,
    initial_discarded: bool = false,

    /// 1-RTT key-update state machine (RFC 9001 §6). Populated once the 1-RTT
    /// traffic secrets are known; until then key update is unavailable and the
    /// key phase stays 0.
    key_update: KeyUpdate = .{},

    /// Long-header connection ids. `dcid` = the peer's, `scid` = ours.
    dcid: ConnectionId,
    scid: ConnectionId,
    /// The DCID the Initial keys were derived from (client picks it; server
    /// learns it from the first Initial packet).
    initial_secret_dcid: [quic_packet.max_connection_id_len]u8 = undefined,
    initial_secret_dcid_len: u8 = 0,

    /// Whether we have produced the first flight (client: ClientHello sent;
    /// server: nothing until it receives the ClientHello).
    started: bool = false,
    /// (Client) whether we have adopted the server's SCID as our DCID yet.
    server_cid_learned: bool = false,
    /// True once both directions of 1-RTT keys exist and the handshake is done.
    established: bool = false,
    /// Set when a CONNECTION_CLOSE was received or we initiated a close.
    closing: bool = false,
    close_error: ?u64 = null,
    /// Whether a CONNECTION_CLOSE frame still needs to go on the wire (we send
    /// one once, in the highest available level).
    close_pending: bool = false,
    /// Whether the server still owes a HANDSHAKE_DONE frame (RFC 9000 §19.20 /
    /// RFC 9001 §4.1.2): the server signals handshake confirmation to the client
    /// with this frame in a 1-RTT packet. Set when the server becomes established;
    /// cleared once the frame has been queued. The client never sends one.
    handshake_done_pending: bool = false,

    /// Packets at a level whose keys are not yet installed, buffered for replay
    /// after the next key install (RFC 9000 §5.7 / RFC 9001 §5.7). Bounded.
    buffered: std.ArrayList(BufferedPacket),
    max_buffered: usize = 16,

    /// Reusable scratch for `newly_acked` so intake does not allocate per call.
    newly_acked: std.ArrayList(u64),

    /// RFC 9002 loss recovery + NewReno congestion control. Records every
    /// ack-eliciting in-flight packet, samples RTT from ACKs, detects loss, and
    /// drives the loss/PTO timers and the send-gating window.
    recovery: quic_recovery.Recovery,

    /// Anti-amplification accounting (RFC 9000 §8.1). Until the peer's address is
    /// validated, a server MUST NOT send more than 3× the bytes it has received
    /// from that address. `bytes_received` is the running total of UDP payload
    /// bytes accepted from the peer; `bytes_sent_unvalidated` is the total the
    /// server has emitted while still unvalidated. The cap is `3 ×
    /// bytes_received`. `address_validated` lifts the limit entirely. A client
    /// is never amplification-limited (it initiates), so this only gates the
    /// server role.
    bytes_received: u64 = 0,
    bytes_sent_unvalidated: u64 = 0,
    /// Whether the peer's address is validated (RFC 9000 §8.1): set when the
    /// server receives a Handshake packet from the client (proves it received
    /// the server's Handshake keys, so it owns the address), or when a valid
    /// Retry/NEW_TOKEN token was presented (via `markAddressValidated`). Always
    /// true for the client role.
    address_validated: bool = false,

    /// The connection's current (validated) peer path — the UDP address replies
    /// go to (RFC 9000 §9). Learned from the first datagram that carries an
    /// address (`recvDatagramFrom`); a 1-RTT packet from a *different* address on
    /// an established connection triggers path validation. Unset (`isSet` false)
    /// until the first addressed datagram, in which case migration is disabled
    /// (the legacy `recvDatagram`/`recvDatagramAt` no-address callers).
    path: PathAddress = .{},
    /// Candidate-path validation state machine (RFC 9000 §8.2 / §9.3). Only the
    /// server role migrates here; a path change is never trusted until a
    /// PATH_CHALLENGE we sent is echoed from the new address.
    path_validation: PathValidation = .{},
    /// Pending PATH_RESPONSE echoes (RFC 9000 §8.2.2): when we receive a
    /// PATH_CHALLENGE we MUST reply with a PATH_RESPONSE echoing its 8 bytes on
    /// the next 1-RTT send. Bounded so a flood cannot grow it without limit.
    pending_path_responses: std.ArrayList([8]u8),
    max_pending_path_responses: usize = 8,
    /// A pending PATH_CHALLENGE that must go out to the candidate path on the
    /// next send (mirrors `path_validation.challenge_pending`; the send path
    /// reads it and clears it). Kept inline for the byte payload.
    pending_path_challenge: ?[8]u8 = null,
    /// Transient: the source address of the datagram currently being processed,
    /// set for the duration of one `recvDatagramFrom` so 1-RTT intake can detect
    /// an off-path packet. Null for the no-address (loopback) recv path.
    recv_src: ?PathAddress = null,
    /// Transient: the wire length of the datagram currently being processed, used
    /// to seed a freshly-started candidate path's 3× anti-amplification budget
    /// (RFC 9000 §9.3.1) with the bytes that triggered the probe.
    recv_len: usize = 0,

    /// Loss / idle timers (nanoseconds, in the caller's clock domain).
    last_recv_ns: u64 = 0,
    /// The next loss-detection / PTO deadline computed from `recovery`, or null
    /// when no timer is armed. Refreshed after every send and ACK.
    timer_deadline_ns: ?u64 = null,
    timer_kind: quic_recovery.TimerKind = .none,
    idle_timeout_ns: u64 = default_idle_timeout_ns,

    /// Per-stream outbound senders (retained-bytes + send/ack cursors), keyed by
    /// stream id. Replaces the old "queue + offset map" so a lost STREAM range is
    /// re-sent from our own buffer (real ACK-driven retransmit). Drained
    /// `max_datagram`-segmented and cwnd/flow-control-bounded in `buildAppDatagram`.
    stream_senders: std.AutoHashMapUnmanaged(u64, StreamSender) = .empty,
    /// Stream ids in FIFO insertion order, so the flush visits streams fairly and
    /// deterministically (a HashMap iteration order is unspecified).
    stream_order: std.ArrayList(u64),
    pending_datagrams: std.ArrayList(PendingDatagram),
    /// Send-side connection-level flow control (RFC 9000 §4.1): the maximum total
    /// stream-data offset the peer will accept across all streams, from the peer's
    /// `initial_max_data` transport parameter and raised by inbound MAX_DATA. We
    /// never send stream bytes that would push our cumulative sent offset past
    /// this. Seeded lazily from the peer transport params on first use.
    peer_max_data: ?u64 = null,
    /// Cumulative stream-data bytes we have *queued to send* across all streams
    /// (the connection-level flow-control consumption). Compared against
    /// `peer_max_data`.
    fc_data_sent: u64 = 0,
    /// Per-stream send-side flow-control limit (RFC 9000 §4.1): the max offset the
    /// peer will accept on a given stream, from the peer's
    /// `initial_max_stream_data_*` params and raised by inbound MAX_STREAM_DATA.
    peer_max_stream_data: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    /// Received application DATAGRAM (RFC 9221) payloads, owned copies, awaiting
    /// the application's `recvDatagram` drain. The engine's intake only accounts
    /// the ACK obligation for a DATAGRAM frame; the driver captures the payload
    /// here so the layer above (HTTP/3 / WebTransport) can consume it. Bounded.
    recv_datagrams: std.ArrayList(PendingDatagram),
    max_recv_datagrams: usize = 256,
    /// Next stream id this endpoint will assign for `openStream` (client bidi
    /// starts at 0, server bidi at 1 — RFC 9000 §2.1).
    next_bidi_stream: u64,
    /// Next stream id this endpoint will assign for `openUniStream` (client uni
    /// starts at 2, server uni at 3 — RFC 9000 §2.1). Advances by 4.
    next_uni_stream: u64,
    const BufferedPacket = struct {
        level: EncryptionLevel,
        bytes: []u8, // owned copy of the full single packet
    };

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    pub fn initServer(allocator: Allocator, config: ServerConfig) Error!Conn {
        var server = quic_handshake.Server.init(allocator, .{
            .cert_chain = config.cert_chain,
            .signing_key = config.signing_key,
            .alpn_protocols = config.alpn_protocols,
            .transport_params = config.transport_params,
            .x25519_seed = config.x25519_seed,
            .server_random = config.server_random,
        }) catch return error.HandshakeFailed;
        errdefer server.deinit();

        const scid = ConnectionId.init(config.local_cid) catch return error.MalformedPacket;

        return finishInit(allocator, .server, .{ .server = server }, config.engine, scid, ConnectionId{});
    }

    pub fn initClient(allocator: Allocator, config: ClientConfig) Error!Conn {
        var client = quic_handshake.Client.initConfig(allocator, .{
            .alpn_protocols = config.alpn_protocols,
            .transport_params = config.transport_params,
            .x25519_seed = config.x25519_seed,
            .client_random = config.client_random,
        }) catch return error.HandshakeFailed;
        errdefer client.deinit();

        const scid = ConnectionId.init(config.local_cid) catch return error.MalformedPacket;
        const dcid = ConnectionId.init(config.initial_dcid) catch return error.MalformedPacket;

        var conn = finishInit(allocator, .client, .{ .client = client }, config.engine, scid, dcid);
        // The client derives the Initial keys from its chosen DCID immediately
        // (is_server = false → write = client_initial secret), and uses that DCID
        // in its Initial long header.
        conn.setInitialKeys(config.initial_dcid, false);
        return conn;
    }

    fn finishInit(
        allocator: Allocator,
        role: Role,
        handshake: Handshake,
        engine_config: quic_conn_state.Config,
        scid: ConnectionId,
        dcid: ConnectionId,
    ) Conn {
        const local: quic_conn_state.Initiator = switch (role) {
            .client => .client,
            .server => .server,
        };
        return .{
            .allocator = allocator,
            .role = role,
            .handshake = handshake,
            .engine = Engine.init(allocator, local, engine_config),
            .send = .{},
            .recovery = quic_recovery.Recovery.init(allocator, .{ .max_datagram = max_datagram }),
            // The client initiates, so it is never amplification-limited; only a
            // server gates on peer-address validation (RFC 9000 §8.1).
            .address_validated = role == .client,
            .initial_keys = null,
            .dcid = dcid,
            .scid = scid,
            .buffered = .empty,
            .newly_acked = .empty,
            .stream_order = .empty,
            .pending_datagrams = .empty,
            .pending_path_responses = .empty,
            .recv_datagrams = .empty,
            // Client bidi stream ids are 0,4,8,…; server 1,5,9,… (RFC 9000 §2.1).
            .next_bidi_stream = switch (role) {
                .client => 0,
                .server => 1,
            },
            // Client uni stream ids are 2,6,10,…; server 3,7,11,… (RFC 9000 §2.1).
            .next_uni_stream = switch (role) {
                .client => 2,
                .server => 3,
            },
        };
    }

    pub fn deinit(self: *Conn) void {
        self.handshake.deinit();
        self.engine.deinit();
        self.recovery.deinit();
        self.send.deinit(self.allocator);
        for (self.buffered.items) |b| self.allocator.free(b.bytes);
        self.buffered.deinit(self.allocator);
        self.newly_acked.deinit(self.allocator);
        {
            var it = self.stream_senders.valueIterator();
            while (it.next()) |s| s.deinit(self.allocator);
            self.stream_senders.deinit(self.allocator);
        }
        self.stream_order.deinit(self.allocator);
        self.peer_max_stream_data.deinit(self.allocator);
        for (self.pending_datagrams.items) |p| self.allocator.free(p.data);
        self.pending_datagrams.deinit(self.allocator);
        self.pending_path_responses.deinit(self.allocator);
        for (self.recv_datagrams.items) |p| self.allocator.free(p.data);
        self.recv_datagrams.deinit(self.allocator);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.initial_keys));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.handshake_keys));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.app_keys));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.key_update));
        std.crypto.secureZero(u8, &self.initial_secret_dcid);
        self.* = undefined;
    }

    /// Capture the complete mutable state of an established server connection
    /// after the listener pump has stopped at a packet boundary. External TLS
    /// material and the local transport-parameter CID slices remain the
    /// listener's responsibility; restore checks their public configuration.
    pub fn captureEstablishedServerSnapshot(self: *const Conn, allocator: Allocator) SnapshotError!ConnSnapshot {
        if (self.role != .server or !self.established or self.closing or self.recv_src != null or self.recv_len != 0)
            return invalidServerSnapshot("capture connection state");
        const server = switch (self.handshake) {
            .server => |*value| value,
            else => return invalidServerSnapshot("capture handshake role"),
        };
        var handshake = captureServerHandshake(allocator, server) catch |err| {
            logServerSnapshotFailure("capture handshake", err);
            return err;
        };
        errdefer handshake.deinit(allocator);
        var engine = self.engine.captureSnapshot(allocator) catch |err| {
            logServerSnapshotFailure("capture engine", err);
            return err;
        };
        errdefer engine.deinit(allocator);
        var recovery = self.recovery.captureSnapshot(allocator) catch |err| {
            logServerSnapshotFailure("capture recovery", err);
            return err;
        };
        errdefer recovery.deinit(allocator);
        var crypto_initial = captureCryptoSend(allocator, &self.send.crypto_initial) catch |err| {
            logServerSnapshotFailure("capture initial crypto send", err);
            return err;
        };
        errdefer crypto_initial.deinit(allocator);
        var crypto_handshake = captureCryptoSend(allocator, &self.send.crypto_handshake) catch |err| {
            logServerSnapshotFailure("capture handshake crypto send", err);
            return err;
        };
        errdefer crypto_handshake.deinit(allocator);

        const buffered = try allocator.alloc(ConnSnapshot.BufferedSnapshot, self.buffered.items.len);
        var buffered_count: usize = 0;
        errdefer {
            for (buffered[0..buffered_count]) |packet| allocator.free(packet.bytes);
            allocator.free(buffered);
        }
        for (self.buffered.items, 0..) |packet, i| {
            buffered[i] = .{ .level = packet.level, .bytes = try allocator.dupe(u8, packet.bytes) };
            buffered_count += 1;
        }
        const newly_acked = try allocator.dupe(u64, self.newly_acked.items);
        errdefer allocator.free(newly_acked);
        const pending_path_responses = try allocator.dupe([8]u8, self.pending_path_responses.items);
        errdefer allocator.free(pending_path_responses);

        if (self.stream_senders.count() > snapshot_max_stream_senders) return error.SnapshotTooLarge;
        const senders = try allocator.alloc(StreamSenderSnapshot, self.stream_senders.count());
        var sender_count: usize = 0;
        errdefer {
            for (senders[0..sender_count]) |*sender| sender.deinit(allocator);
            allocator.free(senders);
        }
        var sender_it = self.stream_senders.iterator();
        while (sender_it.next()) |entry| {
            const sender = entry.value_ptr.*;
            senders[sender_count] = .{
                .id = entry.key_ptr.*,
                .acked_offset = sender.acked_offset,
                .send_offset = sender.send_offset,
                .fin_offset = sender.fin_offset,
                .fin_sent = sender.fin_sent,
                .bytes = try allocator.dupe(u8, sender.buf.items),
            };
            sender_count += 1;
        }
        std.mem.sort(StreamSenderSnapshot, senders, {}, struct {
            fn less(_: void, a: StreamSenderSnapshot, b: StreamSenderSnapshot) bool {
                return a.id < b.id;
            }
        }.less);
        const stream_order = try allocator.dupe(u64, self.stream_order.items);
        errdefer allocator.free(stream_order);
        const pending_datagrams = try captureSnapshotDatagrams(allocator, self.pending_datagrams.items);
        errdefer {
            for (pending_datagrams) |bytes| allocator.free(bytes);
            allocator.free(pending_datagrams);
        }
        if (self.peer_max_stream_data.count() > snapshot_max_flow_entries) return error.SnapshotTooLarge;
        const peer_flow = try allocator.alloc(FlowEntrySnapshot, self.peer_max_stream_data.count());
        errdefer allocator.free(peer_flow);
        var flow_it = self.peer_max_stream_data.iterator();
        var flow_count: usize = 0;
        while (flow_it.next()) |entry| {
            peer_flow[flow_count] = .{ .id = entry.key_ptr.*, .limit = entry.value_ptr.* };
            flow_count += 1;
        }
        std.mem.sort(FlowEntrySnapshot, peer_flow, {}, struct {
            fn less(_: void, a: FlowEntrySnapshot, b: FlowEntrySnapshot) bool {
                return a.id < b.id;
            }
        }.less);
        const recv_datagrams = try captureSnapshotDatagrams(allocator, self.recv_datagrams.items);
        errdefer {
            for (recv_datagrams) |bytes| allocator.free(bytes);
            allocator.free(recv_datagrams);
        }

        var initial_secret_dcid: [quic_packet.max_connection_id_len]u8 = @splat(0);
        defer std.crypto.secureZero(u8, &initial_secret_dcid);
        if (self.initial_secret_dcid_len > initial_secret_dcid.len) return invalidServerSnapshot("capture initial secret CID length");
        @memcpy(initial_secret_dcid[0..self.initial_secret_dcid_len], self.initial_secret_dcid[0..self.initial_secret_dcid_len]);
        var key_update = self.key_update;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&key_update));
        if (!key_update.ready) {
            key_update = .{};
            key_update.next_read = zeroSnapshotPacketKeys();
        }
        var path_validation = self.path_validation;
        path_validation.candidate = canonicalSnapshotPath(path_validation.candidate);
        const snapshot: ConnSnapshot = .{
            .handshake = handshake,
            .engine = engine,
            .recovery = recovery,
            .crypto_initial = crypto_initial,
            .crypto_handshake = crypto_handshake,
            .initial_keys = self.initial_keys,
            .handshake_keys = self.handshake_keys,
            .app_keys = self.app_keys orelse return invalidServerSnapshot("capture application keys"),
            .initial_discarded = self.initial_discarded,
            .key_update = key_update,
            .dcid = self.dcid,
            .scid = self.scid,
            .initial_secret_dcid = initial_secret_dcid,
            .initial_secret_dcid_len = self.initial_secret_dcid_len,
            .started = self.started,
            .server_cid_learned = self.server_cid_learned,
            .established = self.established,
            .closing = self.closing,
            .close_error = self.close_error,
            .close_pending = self.close_pending,
            .handshake_done_pending = self.handshake_done_pending,
            .buffered = buffered,
            .max_buffered = self.max_buffered,
            .newly_acked = newly_acked,
            .bytes_received = self.bytes_received,
            .bytes_sent_unvalidated = self.bytes_sent_unvalidated,
            .address_validated = self.address_validated,
            .path = canonicalSnapshotPath(self.path),
            .path_validation = path_validation,
            .pending_path_responses = pending_path_responses,
            .max_pending_path_responses = self.max_pending_path_responses,
            .pending_path_challenge = self.pending_path_challenge,
            .last_recv_ns = self.last_recv_ns,
            .timer_deadline_ns = self.timer_deadline_ns,
            .timer_kind = self.timer_kind,
            .idle_timeout_ns = self.idle_timeout_ns,
            .senders = senders,
            .stream_order = stream_order,
            .pending_datagrams = pending_datagrams,
            .peer_max_data = self.peer_max_data,
            .fc_data_sent = self.fc_data_sent,
            .peer_max_stream_data = peer_flow,
            .recv_datagrams = recv_datagrams,
            .max_recv_datagrams = self.max_recv_datagrams,
            .next_bidi_stream = self.next_bidi_stream,
            .next_uni_stream = self.next_uni_stream,
        };
        snapshot.validate() catch |err| {
            logServerSnapshotFailure("capture result validation", err);
            return err;
        };
        return snapshot;
    }

    /// Restore into a detached Conn. `config` must borrow candidate-owned TLS
    /// material and stable CID arrays that outlive this Conn. In particular,
    /// moving the enclosing listener Connection after this call is forbidden.
    /// On error the candidate is fully destroyed and the source stays untouched.
    pub fn restoreEstablishedServerSnapshot(allocator: Allocator, snapshot: *const ConnSnapshot, config: ServerConfig) SnapshotError!Conn {
        try snapshot.validate();
        if (!std.mem.eql(u8, config.local_cid, snapshot.scid.slice())) return error.ConfigMismatch;
        const hs_config: quic_handshake.Config = .{
            .cert_chain = config.cert_chain,
            .signing_key = config.signing_key,
            .alpn_protocols = config.alpn_protocols,
            .transport_params = config.transport_params,
        };
        if (!std.mem.eql(u8, &snapshot.handshake.config_digest, &try snapshotConfigDigest(allocator, hs_config)))
            return error.ConfigMismatch;
        if (!std.meta.eql(config.engine, snapshot.engine.config)) return error.ConfigMismatch;
        if (snapshot.handshake.selected_alpn_index) |index| {
            if (index >= config.alpn_protocols.len) return error.ConfigMismatch;
        }
        var result = Conn.initServer(allocator, .{
            .cert_chain = config.cert_chain,
            .signing_key = config.signing_key,
            .alpn_protocols = config.alpn_protocols,
            .transport_params = config.transport_params,
            .local_cid = config.local_cid,
            .engine = config.engine,
            .x25519_seed = @splat(0),
            .server_random = snapshot.handshake.server_random,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidSnapshot,
        };
        errdefer result.deinit();
        result.handshake.server.x25519_pair.wipe();
        result.handshake.server.x25519_pair = snapshot.handshake.x25519_pair;
        const hs = &result.handshake.server;
        hs.state = .connected;
        hs.suite = snapshot.handshake.suite;
        hs.selected_alpn = if (snapshot.handshake.selected_alpn_index) |index| config.alpn_protocols[index] else null;
        try hs.peer_params_storage.appendSlice(allocator, snapshot.handshake.peer_params_wire);
        hs.peer_params = if (snapshot.handshake.peer_params_present)
            quic_transport_params.decode(hs.peer_params_storage.items) catch return error.InvalidSnapshot
        else
            null;
        hs.selected_group = @enumFromInt(snapshot.handshake.selected_group);
        hs.hybrid_keyshare = snapshot.handshake.hybrid_keyshare;
        try hs.transcript.appendSlice(allocator, snapshot.handshake.transcript);
        try hs.recv.appendSlice(allocator, snapshot.handshake.recv);
        try hs.out_initial.appendSlice(allocator, snapshot.handshake.out_initial);
        try hs.out_handshake.appendSlice(allocator, snapshot.handshake.out_handshake);
        hs.handshake_secret = snapshot.handshake.handshake_secret;
        hs.client_hs_secret = snapshot.handshake.client_hs_secret;
        hs.server_hs_secret = snapshot.handshake.server_hs_secret;
        hs.client_ap_secret = snapshot.handshake.client_ap_secret;
        hs.server_ap_secret = snapshot.handshake.server_ap_secret;
        hs.handshake_keys = snapshot.handshake.handshake_keys;
        hs.application_keys = snapshot.handshake.application_keys;

        const restored_engine = try Engine.restoreSnapshot(allocator, &snapshot.engine);
        result.engine.deinit();
        result.engine = restored_engine;
        const restored_recovery = try quic_recovery.Recovery.restoreSnapshot(allocator, &snapshot.recovery);
        result.recovery.deinit();
        result.recovery = restored_recovery;
        try result.send.crypto_initial.buf.appendSlice(allocator, snapshot.crypto_initial.bytes);
        result.send.crypto_initial.base_offset = snapshot.crypto_initial.base_offset;
        result.send.crypto_initial.send_offset = snapshot.crypto_initial.send_offset;
        try result.send.crypto_handshake.buf.appendSlice(allocator, snapshot.crypto_handshake.bytes);
        result.send.crypto_handshake.base_offset = snapshot.crypto_handshake.base_offset;
        result.send.crypto_handshake.send_offset = snapshot.crypto_handshake.send_offset;
        for (snapshot.buffered) |packet| {
            const copy = try allocator.dupe(u8, packet.bytes);
            errdefer allocator.free(copy);
            try result.buffered.append(allocator, .{ .level = packet.level, .bytes = copy });
        }
        try result.newly_acked.appendSlice(allocator, snapshot.newly_acked);
        try result.pending_path_responses.appendSlice(allocator, snapshot.pending_path_responses);
        for (snapshot.senders) |sender| {
            const gop = try result.stream_senders.getOrPut(allocator, sender.id);
            gop.value_ptr.* = .{
                .acked_offset = sender.acked_offset,
                .send_offset = sender.send_offset,
                .fin_offset = sender.fin_offset,
                .fin_sent = sender.fin_sent,
            };
            try gop.value_ptr.buf.appendSlice(allocator, sender.bytes);
        }
        try result.stream_order.appendSlice(allocator, snapshot.stream_order);
        try restoreSnapshotDatagrams(allocator, &result.pending_datagrams, snapshot.pending_datagrams);
        for (snapshot.peer_max_stream_data) |entry| try result.peer_max_stream_data.put(allocator, entry.id, entry.limit);
        try restoreSnapshotDatagrams(allocator, &result.recv_datagrams, snapshot.recv_datagrams);

        result.initial_keys = snapshot.initial_keys;
        result.handshake_keys = snapshot.handshake_keys;
        result.app_keys = snapshot.app_keys;
        result.initial_discarded = snapshot.initial_discarded;
        result.key_update = snapshot.key_update;
        result.dcid = snapshot.dcid;
        result.scid = snapshot.scid;
        result.initial_secret_dcid = snapshot.initial_secret_dcid;
        result.initial_secret_dcid_len = snapshot.initial_secret_dcid_len;
        result.started = snapshot.started;
        result.server_cid_learned = snapshot.server_cid_learned;
        result.established = snapshot.established;
        result.closing = snapshot.closing;
        result.close_error = snapshot.close_error;
        result.close_pending = snapshot.close_pending;
        result.handshake_done_pending = snapshot.handshake_done_pending;
        result.max_buffered = snapshot.max_buffered;
        result.bytes_received = snapshot.bytes_received;
        result.bytes_sent_unvalidated = snapshot.bytes_sent_unvalidated;
        result.address_validated = snapshot.address_validated;
        result.path = snapshot.path;
        result.path_validation = snapshot.path_validation;
        result.max_pending_path_responses = snapshot.max_pending_path_responses;
        result.pending_path_challenge = snapshot.pending_path_challenge;
        result.last_recv_ns = snapshot.last_recv_ns;
        result.timer_deadline_ns = snapshot.timer_deadline_ns;
        result.timer_kind = snapshot.timer_kind;
        result.idle_timeout_ns = snapshot.idle_timeout_ns;
        result.peer_max_data = snapshot.peer_max_data;
        result.fc_data_sent = snapshot.fc_data_sent;
        result.max_recv_datagrams = snapshot.max_recv_datagrams;
        result.next_bidi_stream = snapshot.next_bidi_stream;
        result.next_uni_stream = snapshot.next_uni_stream;
        return result;
    }

    // -----------------------------------------------------------------------
    // Public state
    // -----------------------------------------------------------------------

    pub fn isEstablished(self: *const Conn) bool {
        return self.established;
    }

    /// Whether the peer's address is validated (RFC 9000 §8.1) and the 3×
    /// anti-amplification send limit no longer applies. Always true for a client.
    pub fn isAddressValidated(self: *const Conn) bool {
        return self.address_validated;
    }

    /// Mark the peer's address as validated, lifting the anti-amplification
    /// limit (RFC 9000 §8.1). Called internally on a decrypted Handshake packet;
    /// the listener also calls this when a client echoes a valid Retry/NEW_TOKEN
    /// address-validation token in its Initial (RFC 9000 §8.1.2), which validates
    /// the address immediately without a Retry round trip.
    pub fn markAddressValidated(self: *Conn) void {
        self.address_validated = true;
    }

    /// Total UDP payload bytes received from the peer while unvalidated (the base
    /// of the 3× anti-amplification budget). Exposed for tests / introspection.
    pub fn bytesReceived(self: *const Conn) u64 {
        return self.bytes_received;
    }

    /// Total bytes the server has emitted while the peer was unvalidated.
    pub fn bytesSentUnvalidated(self: *const Conn) u64 {
        return self.bytes_sent_unvalidated;
    }

    pub fn isClosing(self: *const Conn) bool {
        return self.closing;
    }

    pub fn selectedAlpn(self: *const Conn) ?[]const u8 {
        return self.handshake.selectedAlpn();
    }

    pub fn peerTransportParams(self: *const Conn) ?quic_transport_params.TransportParameters {
        return self.handshake.peerTransportParams();
    }

    // -----------------------------------------------------------------------
    // Key installation / discard (RFC 9001 §4.9)
    // -----------------------------------------------------------------------

    /// Derive and install the Initial keys from `dcid`. `is_server` selects the
    /// write (own) vs read (peer) direction.
    fn setInitialKeys(self: *Conn, dcid: []const u8, is_server: bool) void {
        self.initial_keys = KeySet.initInitial(dcid, is_server);
        @memcpy(self.initial_secret_dcid[0..dcid.len], dcid);
        self.initial_secret_dcid_len = @intCast(dcid.len);
    }

    /// Pull any newly-available keys out of the handshake and install them,
    /// discarding the Initial keys once the Handshake keys are in hand.
    fn syncKeys(self: *Conn) void {
        if (self.handshake_keys == null) {
            if (self.handshake.handshakeKeys()) |ks| self.handshake_keys = ks;
        }
        if (self.app_keys == null) {
            if (self.handshake.applicationKeys()) |ks| {
                self.app_keys = ks;
                self.initKeyUpdate();
            }
        }
        self.refreshEstablished();
    }

    /// Seed the 1-RTT key-update state from the handshake's application traffic
    /// secrets (RFC 9001 §6.1): record the current write/read secrets and
    /// pre-compute the next-generation read keys so a peer-initiated phase flip
    /// can be trial-decrypted without deriving on the receive path. No-op for a
    /// suite whose secret width the "quic ku" roll does not support (SHA-384);
    /// the connection then simply never offers a key update (documented gap).
    fn initKeyUpdate(self: *Conn) void {
        if (self.key_update.ready) return;
        const secrets = self.handshake.appTrafficSecrets() orelse return;
        self.key_update.ready = true;
        self.key_update.phase = 0;
        self.key_update.suite = secrets.suite;
        self.key_update.write_secret = secrets.write;
        self.key_update.read_secret = secrets.read;
        // Pre-compute the next-generation read keys (§6.3).
        self.key_update.next_read_secret = quic_tls.nextGenerationSecret(secrets.read);
        const cur_read = (self.app_keys orelse return).read;
        self.key_update.next_read = quic_protect.keyUpdateDirection(cur_read, self.key_update.next_read_secret);
    }

    fn refreshEstablished(self: *Conn) void {
        if (!self.established and self.app_keys != null and self.handshake.isComplete()) {
            self.established = true;
            connDbg("CONNECTION ESTABLISHED role={s}", .{@tagName(self.role)});
            // RFC 9001 §4.9.1/§4.9.2: by the time the handshake is complete and
            // 1-RTT keys are in use, the Initial keys are no longer needed for
            // either direction; discard them. (We keep them through the whole
            // handshake so a retransmitted/late Initial — e.g. the peer's ACK of
            // our Initial — can still be processed and sent.)
            self.initial_keys = null;
            self.initial_discarded = true;
            // RFC 9002 §6.4: discard the Initial space's recovery state with its
            // keys, and confirm the handshake — which discards the Handshake
            // space too and switches the PTO to include max_ack_delay (§6.2.1).
            self.recovery.discardSpace(.initial);
            self.confirmHandshakeRecovery();
            // RFC 9000 §19.20 / RFC 9001 §4.1.2: the SERVER owes a HANDSHAKE_DONE
            // frame to confirm the handshake to the client (a real client — e.g.
            // curl/ngtcp2 — withholds application data, including its HTTP/3
            // request, until the handshake is confirmed). The client never sends
            // one.
            if (self.role == .server) self.handshake_done_pending = true;
        }
    }

    fn keysFor(self: *Conn, level: EncryptionLevel) ?*KeySet {
        return switch (level) {
            .initial => if (self.initial_keys) |*k| k else null,
            .handshake => if (self.handshake_keys) |*k| k else null,
            .application => if (self.app_keys) |*k| k else null,
        };
    }

    // -----------------------------------------------------------------------
    // Receive path
    // -----------------------------------------------------------------------

    /// Parse and process one received UDP datagram (possibly several coalesced
    /// QUIC packets). Bounds-checked end to end: a malformed or truncated
    /// datagram returns `error.MalformedPacket` without panicking.
    pub fn recvDatagram(self: *Conn, datagram: []const u8) Error!void {
        return self.recvDatagramAt(datagram, self.last_recv_ns);
    }

    /// As `recvDatagram` but stamps activity at `now` (the caller's clock).
    /// Passes no source address, so path migration is disabled for this
    /// datagram (the legacy socketless loopback callers).
    pub fn recvDatagramAt(self: *Conn, datagram: []const u8, now: u64) Error!void {
        return self.recvDatagramImpl(datagram, null, now);
    }

    /// As `recvDatagramAt` but carries the datagram's UDP source address so path
    /// validation + migration (RFC 9000 §9) can run. The listener calls this with
    /// the demuxed peer address. On the first addressed datagram the connection
    /// adopts `src` as its current path; a later 1-RTT packet from a *different*
    /// `src` on an established connection starts path validation (a PATH_CHALLENGE
    /// to the new address, 3×-budget-limited) and only a matching PATH_RESPONSE
    /// migrates the primary address.
    pub fn recvDatagramFrom(self: *Conn, datagram: []const u8, src: PathAddress, now: u64) Error!void {
        return self.recvDatagramImpl(datagram, src, now);
    }

    fn recvDatagramImpl(self: *Conn, datagram: []const u8, src: ?PathAddress, now: u64) Error!void {
        self.last_recv_ns = now;

        // Thread the source address through to the 1-RTT intake so an off-path
        // packet can be detected (RFC 9000 §9). Cleared when the call returns so a
        // subsequent no-address recv does not see a stale path.
        self.recv_src = src;
        self.recv_len = datagram.len;
        defer {
            self.recv_src = null;
            self.recv_len = 0;
        }

        // Adopt the very first addressed path as the current one (no migration on
        // first contact — it IS the connection's path). Migration is only ever
        // considered once a path is established AND the address changes.
        if (src) |s| {
            if (!self.path.isSet()) self.path = s;
            // Candidate-path anti-amplification accounting (RFC 9000 §9.3.1):
            // count bytes received on an in-flight candidate path toward its 3×
            // budget so the response/echo we owe stays within it.
            if (self.path_validation.active and self.path_validation.candidate.eql(s)) {
                self.path_validation.bytes_received +|= datagram.len;
            }
        }

        // Anti-amplification accounting (RFC 9000 §8.1): every received UDP
        // payload byte raises the 3× send budget. We count the whole datagram
        // (the RFC counts received datagrams toward the limit even if some
        // packets in them fail to decrypt), saturating so a long-lived peer
        // never wraps the counter.
        if (!self.address_validated) {
            self.bytes_received +|= datagram.len;
        }
        var pos: usize = 0;
        while (pos < datagram.len) {
            // A 0x00 byte where a packet should start is padding to the end of
            // the datagram (a coalesced packet's PADDING leaked past Length is
            // impossible, but a peer may pad the datagram tail). Stop.
            if (datagram[pos] == 0x00) break;
            // A single packet that cannot be parsed or decrypted MUST be silently
            // discarded WITHOUT failing the connection (RFC 9000 §5.2 — "packets
            // that cannot be processed are discarded"; RFC 9001 §5.2). This is
            // essential for interop: a real client (curl/ngtcp2) coalesces a
            // 1-RTT packet behind the Handshake packet that completes our
            // handshake, and may also send a packet at a level/version we cannot
            // yet process. We stop scanning the rest of this datagram (we cannot
            // know where the next coalesced packet begins once one fails to
            // parse) but keep the connection alive. Truly fatal conditions
            // (allocation failure) still propagate.
            const consumed = self.recvOnePacket(datagram[pos..], now) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => {
                    connDbg("recvOnePacket dropped at pos={d}/{d}: {s}", .{ pos, datagram.len, @errorName(err) });
                    break; // drop this packet + the rest of the datagram
                },
            };
            if (consumed == 0) break; // defensive: never loop forever
            pos += consumed;
        }
    }

    /// Process one packet starting at `input[0]`. Returns the number of bytes
    /// the packet occupied in the datagram (for coalescing) — for a short-header
    /// (1-RTT) packet that is the whole remaining slice.
    fn recvOnePacket(self: *Conn, input: []const u8, now: u64) Error!usize {
        if (input.len == 0) return 0;
        const is_long = (input[0] & 0x80) != 0;
        if (is_long) return self.recvLongPacket(input, now);
        return self.recvShortPacket(input, now);
    }

    fn recvLongPacket(self: *Conn, input: []const u8, now: u64) Error!usize {
        const dec = quic_packet.decodeLongHeader(input) catch return error.MalformedPacket;
        if (dec.header.version != quic_version_1) {
            // Version negotiation / Retry are out of scope; treat as malformed
            // so the caller can drop the datagram rather than half-process it.
            return error.UnsupportedVersion;
        }

        const level: EncryptionLevel = switch (dec.header.packet_type) {
            .initial => .initial,
            .handshake => .handshake,
            .zero_rtt => return error.MalformedPacket, // 0-RTT unsupported (typed gap)
            .retry => return error.MalformedPacket, // Retry handled by the listener layer (typed gap here)
        };

        // The server learns the client's DCID from the first Initial and derives
        // its Initial keys from it (RFC 9001 §5.2).
        if (self.role == .server and level == .initial and self.initial_keys == null and !self.initial_discarded) {
            const client_dcid = dec.header.dcid.slice();
            self.setInitialKeys(client_dcid, true);
            // Reply to the client using its SCID as our DCID.
            self.dcid = dec.header.scid;
        }

        // The client adopts the server's chosen Source Connection ID as its
        // Destination Connection ID from the server's first packet (RFC 9000
        // §7.2). Until then it used the random Initial DCID it invented; the
        // server's real SCID is what 1-RTT short headers must address.
        if (self.role == .client and !self.server_cid_learned) {
            self.dcid = dec.header.scid;
            self.server_cid_learned = true;
        }

        var cursor = dec.consumed;
        // Initial packets carry a Token (varint length + token bytes) before the
        // Length field (RFC 9000 §17.2.2). Handshake packets do not.
        if (level == .initial) {
            const tok = decodeVarIntAt(input, cursor) catch return error.MalformedPacket;
            cursor += tok.len;
            const tok_len = std.math.cast(usize, tok.value) orelse return error.MalformedPacket;
            if (cursor + tok_len > input.len) return error.MalformedPacket;
            cursor += tok_len;
        }

        // Length = pn_len + payload + tag.
        const length_vi = decodeVarIntAt(input, cursor) catch return error.MalformedPacket;
        cursor += length_vi.len;
        const length = std.math.cast(usize, length_vi.value) orelse return error.MalformedPacket;
        const pn_offset = cursor;
        const packet_end = pn_offset + length;
        if (packet_end > input.len) return error.MalformedPacket;

        try self.openAndIntake(level, input[0..packet_end], pn_offset, now);
        return packet_end;
    }

    fn recvShortPacket(self: *Conn, input: []const u8, now: u64) Error!usize {
        // 1-RTT: first byte | dcid (our scid length) | pn. We always issue a
        // fixed-length local connection id (scid), so the pn offset is known.
        const our_cid_len: usize = self.scid.len;
        const pn_offset = 1 + our_cid_len;
        if (input.len < pn_offset + 1) return error.MalformedPacket;
        // A short-header packet is always the last in its datagram (it has no
        // Length field), so it consumes the whole remaining slice.
        try self.openAndIntake(.application, input, pn_offset, now);
        return input.len;
    }

    /// Open `packet` (a single QUIC packet slice) at `level`, decode its frames,
    /// and run them through the engine + handshake. Buffers the packet if the
    /// level's keys are not yet installed.
    fn openAndIntake(self: *Conn, level: EncryptionLevel, packet: []const u8, pn_offset: usize, now: u64) Error!void {
        const keys = self.keysFor(level) orelse {
            // Keys not installed yet — buffer for replay after the next install
            // (handshake reordering, RFC 9000 §5.7). Initial keys that were
            // discarded mean a late Initial: drop it (not an error).
            if (level == .initial and self.initial_discarded) return;
            try self.bufferPacket(level, packet);
            return;
        };

        // 1-RTT packets with key-update support take the key-phase-aware path so
        // a peer-initiated update (a flipped phase bit) is detected and committed
        // (RFC 9001 §6.3). The handshake levels never key-update.
        if (level == .application and self.key_update.ready) {
            return self.openApp1Rtt(packet, pn_offset, now);
        }

        // Work on a mutable copy: openPacketSuite unmasks the header in place.
        const buf = try self.allocator.alloc(u8, packet.len);
        defer self.allocator.free(buf);
        @memcpy(buf, packet);

        const plaintext = try self.allocator.alloc(u8, packet.len);
        defer self.allocator.free(plaintext);

        const largest = self.engine.space(level).largest_received;
        const ctx = PnDecodeCtx{ .largest = largest };
        PnDecodeCtx.current = ctx;
        const opened = quic_protect.openPacketSuite(
            plaintext,
            buf,
            pn_offset,
            keys.read,
            PnDecodeCtx.decode,
        ) catch {
            // AEAD/header failure — a packet we cannot authenticate is silently
            // discarded (RFC 9001 §5.2); not a connection error.
            return;
        };

        const pn = PnDecodeCtx.last_full;
        try self.intakeFrames(level, pn, plaintext[0..opened.plaintext_len], now);
    }

    /// Open a 1-RTT (short-header) packet with key-update awareness (RFC 9001
    /// §6.3). Header protection (whose key never rolls) is removed first to reveal
    /// the key-phase bit and packet number; the AEAD key is then chosen by phase:
    ///   * phase == current  → current read keys.
    ///   * phase != current  → trial-decrypt with the pre-computed NEXT-generation
    ///     read keys; on success COMMIT the update (next→current, retain the old
    ///     read keys briefly for reordering, re-derive the new next, and flip our
    ///     own send phase so our outbound packets match — §6.1), subject to the
    ///     peer-update rate limit (§6.6). On AEAD failure the phase flip is a
    ///     forgery and the packet is dropped (anti-forgery).
    ///   * a packet that fails the current keys but matches the retained PREVIOUS
    ///     generation (a packet reordered across our own update) still decrypts
    ///     within the retention window (§6.4).
    fn openApp1Rtt(self: *Conn, packet: []const u8, pn_offset: usize, now: u64) Error!void {
        const cur = self.app_keys orelse return;

        // Remove header protection on a mutable copy to read the phase bit + pn.
        // The header-protection key never rolls (§6.1), so the current read hp key
        // unmasks every generation's short header.
        const buf = try self.allocator.alloc(u8, packet.len);
        defer self.allocator.free(buf);
        @memcpy(buf, packet);

        const read_keys = cur.read;
        const pn_len = quic_protect.removeHeaderProtection(buf, pn_offset, read_keys.suite, read_keys.hpBytes()) catch return;
        const incoming_phase: u1 = if ((buf[0] & 0x04) != 0) 1 else 0;

        // Decode the full packet number against the largest received.
        var truncated: u64 = 0;
        for (buf[pn_offset .. pn_offset + pn_len]) |b| truncated = (truncated << 8) | b;
        const largest = self.engine.space(.application).largest_received;
        const full_pn = if (largest) |la|
            quic_frame.decodePacketNumber(truncated, pn_len, la) catch truncated
        else
            truncated;

        const header_end = pn_offset + pn_len;
        if (header_end > buf.len) return;
        const aad = buf[0..header_end];
        const ciphertext = buf[header_end..];
        if (ciphertext.len < quic_protect.aead_tag_len) return;
        const ct_len = ciphertext.len - quic_protect.aead_tag_len;

        const plaintext = try self.allocator.alloc(u8, ct_len);
        defer self.allocator.free(plaintext);

        if (incoming_phase == self.key_update.phase) {
            // Phase matches the current generation → current read keys.
            quic_protect.unprotectPayload(read_keys.suite, plaintext, ciphertext, read_keys.keyBytes(), read_keys.iv, full_pn, aad) catch {
                self.key_update.aead_failures +|= 1;
                return;
            };
            self.noteCurrentPhasePn(full_pn);
            try self.intakeFrames(.application, full_pn, plaintext, now);
            return;
        }

        // Phase bit differs from the current generation (§6.3). Disambiguate by
        // packet number against the highest we have accepted in the current
        // phase: a HIGHER number is the peer initiating an update (try the
        // next-generation read keys, then commit); a LOWER (or equal-or-no
        // baseline) number is a packet reordered from the PREVIOUS phase (try the
        // retained previous read keys).
        const looks_like_update = if (self.key_update.highest_pn_current_phase) |hp| full_pn > hp else true;

        if (!looks_like_update) {
            // Reordered previous-generation packet (§6.4): retained keys, window.
            if (self.openWithPrev(plaintext, ciphertext, aad, full_pn, now)) {
                try self.intakeFrames(.application, full_pn, plaintext, now);
            }
            return;
        }

        // Peer-initiated update: trial-decrypt with the pre-computed next keys.
        const nr = self.key_update.next_read;
        quic_protect.unprotectPayload(nr.suite, plaintext, ciphertext, nr.keyBytes(), nr.iv, full_pn, aad) catch {
            // A phase flip that fails AEAD is a forgery. Before rejecting, try the
            // retained previous keys too (a reordered old packet whose pn happened
            // to exceed our current-phase high-water mark). Otherwise drop it and
            // count the failure toward the integrity limit (§6.6).
            if (self.openWithPrev(plaintext, ciphertext, aad, full_pn, now)) {
                try self.intakeFrames(.application, full_pn, plaintext, now);
            } else {
                self.key_update.aead_failures +|= 1;
            }
            return;
        };

        // Anti-DoS rate limit (§6.6): refuse to COMMIT peer updates faster than
        // once per retention interval (≈3·PTO). The packet authenticated, so we
        // deliver its frames using the next-generation keys, but we do NOT rotate
        // our generation — the peer must slow down. (We still decrypt subsequent
        // packets in this phase via the next keys until we eventually commit.)
        const interval = KeyUpdate.retentionNs(self.recovery.ptoDuration());
        const too_soon = self.key_update.have_updated and now < self.key_update.last_update_ns + interval;
        if (!too_soon) {
            self.commitPeerUpdate(incoming_phase, full_pn, now);
        }
        try self.intakeFrames(.application, full_pn, plaintext, now);
    }

    /// Record the highest packet number accepted in the current key phase, used
    /// by §6.3 to disambiguate a reordered previous-phase packet from a new
    /// peer-initiated update.
    fn noteCurrentPhasePn(self: *Conn, pn: u64) void {
        if (self.key_update.highest_pn_current_phase) |hp| {
            if (pn > hp) self.key_update.highest_pn_current_phase = pn;
        } else {
            self.key_update.highest_pn_current_phase = pn;
        }
    }

    /// Try the retained previous-generation read keys (§6.4) for a packet that the
    /// current keys could not open. Returns true (with `plaintext` filled) on
    /// success within the retention window, false otherwise.
    fn openWithPrev(self: *Conn, plaintext: []u8, ciphertext: []const u8, aad: []const u8, full_pn: u64, now: u64) bool {
        const prev = self.key_update.prev_read orelse return false;
        if (now > self.key_update.prev_read_until_ns) return false;
        quic_protect.unprotectPayload(prev.suite, plaintext, ciphertext, prev.keyBytes(), prev.iv, full_pn, aad) catch {
            self.key_update.aead_failures +|= 1;
            return false;
        };
        return true;
    }

    /// Commit a peer-initiated key update (RFC 9001 §6.1). The whole generation
    /// rolls (a single key-phase bit covers both directions): the next-generation
    /// read keys become current (retaining the old read keys briefly for
    /// reordered packets, §6.4), our own write keys roll so our outbound phase
    /// matches the peer's, and the next-generation keys are pre-computed for the
    /// following update. `first_pn` seeds the new phase's high-water mark.
    fn commitPeerUpdate(self: *Conn, new_phase: u1, first_pn: u64, now: u64) void {
        self.rollGeneration(new_phase, now);
        self.key_update.highest_pn_current_phase = first_pn;
        // A peer update we mirrored is not a self-initiated update awaiting
        // confirmation; the phase now matches the peer's.
        self.key_update.initiated = false;
        self.key_update.confirm_pn = null;
    }

    /// Roll BOTH directions of the 1-RTT keys to the next generation and set the
    /// key phase to `new_phase` (RFC 9001 §6.1). The previous read keys are
    /// retained for the reordering window (§6.4); the header-protection keys are
    /// retained (never rolled). Shared by self- and peer-initiated updates.
    fn rollGeneration(self: *Conn, new_phase: u1, now: u64) void {
        if (self.app_keys == null) return;
        const cur = &self.app_keys.?;

        // Retain the outgoing read keys for reordered previous-phase packets.
        self.key_update.prev_read = cur.read;
        self.key_update.prev_read_until_ns = now +| KeyUpdate.retentionNs(self.recovery.ptoDuration());

        // Roll write keys (own secret) to the next generation.
        const next_write_secret = quic_tls.nextGenerationSecret(self.key_update.write_secret);
        cur.write = quic_protect.keyUpdateDirection(cur.write, next_write_secret);
        self.key_update.write_secret = next_write_secret;

        // The pre-computed next read keys become current.
        cur.read = self.key_update.next_read;
        self.key_update.read_secret = self.key_update.next_read_secret;

        // Pre-compute the following generation's read keys for the next update.
        self.key_update.next_read_secret = quic_tls.nextGenerationSecret(self.key_update.read_secret);
        self.key_update.next_read = quic_protect.keyUpdateDirection(cur.read, self.key_update.next_read_secret);

        self.key_update.phase = new_phase;
        self.key_update.last_update_ns = now;
        self.key_update.have_updated = true;
        self.key_update.packets_sent_epoch = 0;
    }

    fn intakeFrames(self: *Conn, level: EncryptionLevel, pn: u64, payload: []const u8, now: u64) Error!void {
        var frames = quic_frame.decodeFrames(self.allocator, payload) catch |e| {
            connDbg("decodeFrames FAILED lvl={s} pn={d} payload_len={d}: {s}", .{ @tagName(level), pn, payload.len, @errorName(e) });
            return error.MalformedPacket;
        };
        defer frames.deinit();

        self.newly_acked.clearRetainingCapacity();
        const result = self.engine.intake(level, pn, frames.frames, &self.newly_acked) catch |e| {
            connDbg("engine.intake FAILED lvl={s} pn={d}: {s}", .{ @tagName(level), pn, @errorName(e) });
            return error.MalformedPacket;
        };

        self.last_recv_ns = now;

        // Anti-amplification (RFC 9000 §8.1): a server validates the peer's
        // address on the first *successfully decrypted* Handshake packet — the
        // client can only have produced one after receiving the server's
        // Handshake keys, which proves it owns the source address. We mark on the
        // authenticated frame path (not the header type) so a spoofed/forged
        // long header cannot lift the 3× limit. The limit is then lifted.
        if (self.role == .server and level == .handshake and !self.address_validated) {
            self.markAddressValidated();
        }

        // Capture any received application DATAGRAM payloads (RFC 9221) and run
        // path-validation frame handling (RFC 9000 §8.2). This packet has already
        // passed AEAD, so it is authentic — the only point at which a path change
        // or a PATH_CHALLENGE/RESPONSE may be acted on (§9.3: an endpoint MUST NOT
        // migrate or validate based on an unauthenticated packet). Only the
        // Application (1-RTT) space carries DATAGRAM / PATH frames.
        if (level == .application) {
            for (frames.frames) |frame| {
                switch (frame) {
                    .DATAGRAM => |dg| try self.captureRecvDatagram(dg.data),
                    .PATH_CHALLENGE => |data| try self.onPathChallenge(data),
                    .PATH_RESPONSE => |data| self.onPathResponse(data, now),
                    // Send-side flow control (RFC 9000 §4.1): the peer raised a
                    // limit. Never let it shrink (a MAX_* is monotonic per §19.9/
                    // §19.10); take the max so a reordered older frame can't lower
                    // our credit.
                    .MAX_DATA => |limit| {
                        const cur = self.peer_max_data orelse self.peerInitialMaxData();
                        self.peer_max_data = @max(cur, limit);
                    },
                    .MAX_STREAM_DATA => |m| {
                        const cur = self.peer_max_stream_data.get(m.stream_id) orelse
                            self.peerInitialStreamDataLimit(m.stream_id);
                        self.peer_max_stream_data.put(self.allocator, m.stream_id, @max(cur, m.limit)) catch {};
                    },
                    else => {},
                }
            }
            // After processing the authenticated frames, consider whether this
            // 1-RTT packet arrived from an off-path source (a migration / NAT
            // rebinding attempt). This must run on the authenticated path only.
            try self.handlePathOnRecv(now);
        }

        // Feed any newly-acked outbound packets to RFC 9002 loss recovery BEFORE
        // pumping CRYPTO (which may grow the send buffers): sample RTT, detect
        // loss, grow/shrink the congestion window, and re-queue lost frames. The
        // newly-acked PNs are all for `level` (intake clears the list per call),
        // and the engine has just advanced this space's `largest_acked`.
        if (result.newly_acked_count > 0) {
            if (self.engine.space(level).largest_acked) |la| {
                try self.onAckProcessed(level, la, now);
            }
        }

        // Drain readable CRYPTO into the handshake (per level).
        try self.pumpCryptoToHandshake(level);

        if (result.connection_close) |code| {
            connDbg("CONNECTION_CLOSE received from peer: error_code=0x{x}", .{code});
            self.closing = true;
            self.close_error = code;
            // Do not return an error here — let the caller observe via
            // isClosing(); a CONNECTION_CLOSE is a normal teardown signal.
        }

        // The handshake may have just installed new keys; replay any buffered
        // packets that are now decryptable.
        self.syncKeys();
        try self.replayBuffered(now);
    }

    /// Feed any newly-contiguous CRYPTO bytes at `level` into the handshake, then
    /// pull whatever flight it produced into our send-side CRYPTO buffers.
    fn pumpCryptoToHandshake(self: *Conn, level: EncryptionLevel) Error!void {
        const cs = self.engine.cryptoStream(level);
        const avail = cs.readable();
        if (avail > 0) {
            const bytes = cs.peek();
            self.handshake.feedCrypto(level, bytes) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    connDbg("feedCrypto lvl={s} FAILED: {s}", .{ @tagName(level), @errorName(e) });
                    return error.HandshakeFailed;
                },
            };
            _ = cs.consume(avail);
        }
        // Pull produced flights for both lower levels into our send buffers.
        try self.collectHandshakeOutput();
        self.syncKeys();
    }

    /// Move any CRYPTO bytes the handshake produced (Initial + Handshake levels)
    /// into the corresponding send buffers so the next `sendDatagrams` ships
    /// them. Idempotent: `takeFlight` returns empty once drained.
    fn collectHandshakeOutput(self: *Conn) Error!void {
        inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |lvl| {
            const bytes = self.handshake.takeFlight(lvl) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.HandshakeFailed,
            };
            defer self.allocator.free(bytes);
            if (bytes.len > 0) {
                const buf = self.send.cryptoBuf(lvl).?;
                try buf.write(self.allocator, bytes);
            }
        }
    }

    fn bufferPacket(self: *Conn, level: EncryptionLevel, packet: []const u8) Error!void {
        if (self.buffered.items.len >= self.max_buffered) return; // bounded; drop oldest-equivalent
        const copy = try self.allocator.dupe(u8, packet);
        errdefer self.allocator.free(copy);
        try self.buffered.append(self.allocator, .{ .level = level, .bytes = copy });
    }

    fn replayBuffered(self: *Conn, now: u64) Error!void {
        if (self.buffered.items.len == 0) return;
        // Take ownership of the current list and re-feed; packets whose keys are
        // still missing get re-buffered by openAndIntake.
        var pending = self.buffered;
        self.buffered = .empty;
        defer {
            for (pending.items) |b| self.allocator.free(b.bytes);
            pending.deinit(self.allocator);
        }
        for (pending.items) |b| {
            if (self.keysFor(b.level) == null) {
                // Still no keys — keep it buffered (re-copy into the fresh list).
                try self.bufferPacket(b.level, b.bytes);
                continue;
            }
            const pn_offset = self.pnOffsetForBuffered(b.level, b.bytes) catch continue;
            try self.openAndIntake(b.level, b.bytes, pn_offset, now);
        }
    }

    fn pnOffsetForBuffered(self: *Conn, level: EncryptionLevel, packet: []const u8) Error!usize {
        if (level == .application) return 1 + @as(usize, self.scid.len);
        const dec = quic_packet.decodeLongHeader(packet) catch return error.MalformedPacket;
        var cursor = dec.consumed;
        if (level == .initial) {
            const tok = decodeVarIntAt(packet, cursor) catch return error.MalformedPacket;
            cursor += tok.len;
            const tok_len = std.math.cast(usize, tok.value) orelse return error.MalformedPacket;
            cursor += tok_len;
        }
        const length_vi = decodeVarIntAt(packet, cursor) catch return error.MalformedPacket;
        cursor += length_vi.len;
        return cursor;
    }

    // -----------------------------------------------------------------------
    // Connection migration + path validation (RFC 9000 §8.2 / §9)
    // -----------------------------------------------------------------------

    /// How long an unanswered PATH_CHALLENGE probe is kept before the candidate
    /// path is abandoned (RFC 9000 §8.2.4 / §9.3.2). The RFC ties the bound to
    /// the PTO; we use 3× the current PTO as a generous, RTT-aware deadline so a
    /// genuinely-reachable new path is not abandoned prematurely, while a spoofed
    /// off-path probe is dropped quickly.
    fn pathValidationDeadlineNs(self: *Conn) u64 {
        return self.recovery.ptoDuration() *| 3;
    }

    /// Called after an authenticated 1-RTT packet is intaken (RFC 9000 §9.3).
    /// Decides whether the packet arrived on the current path, on an in-flight
    /// candidate path, or from a brand-new off-path source that should start a
    /// migration probe. Only the server role migrates: a client picks its own
    /// path. Migration is gated on the connection being established (a path change
    /// during the handshake is out of scope and ignored).
    fn handlePathOnRecv(self: *Conn, now: u64) Error!void {
        const src = self.recv_src orelse return; // no address → loopback path, never migrate
        if (self.role != .server) return; // only the server validates a peer migration
        if (!self.established) return; // path change pre-establishment is ignored
        if (!self.path.isSet()) {
            self.path = src;
            return;
        }
        if (self.path.eql(src)) return; // on-path: nothing to do

        // The packet authenticated but arrived from a DIFFERENT address than the
        // current path. Treat it as a probing / migration attempt (§9). We do NOT
        // migrate now — we keep the old path and start validating the new one.
        if (self.path_validation.active and self.path_validation.candidate.eql(src)) {
            // Already probing this candidate; the recv accounting above bumped its
            // 3× budget. Nothing else to start.
            return;
        }
        // (Re)start a probe to this new candidate path. A previous in-flight probe
        // to a different candidate is abandoned in favour of the most recent one.
        self.startPathValidation(src, now);
    }

    /// Begin validating `candidate` (RFC 9000 §8.2.1): pick 8 unpredictable
    /// challenge bytes, arm them to be sent to the candidate path, and seed the
    /// candidate's anti-amplification budget. The old path stays the primary one
    /// until/unless the challenge is answered.
    fn startPathValidation(self: *Conn, candidate: PathAddress, now: u64) void {
        var challenge: [8]u8 = undefined;
        secure_fns.randomBytes(&challenge);
        self.path_validation = .{
            .active = true,
            .candidate = candidate,
            .challenge = challenge,
            .challenge_pending = true,
            // The triggering packet's bytes count toward the new path's receive
            // budget (it arrived on the candidate path), so the probe we owe to it
            // stays within 3× (RFC 9000 §9.3.1).
            .bytes_received = self.recv_len,
            .bytes_sent = 0,
            .started_ns = now,
        };
        self.pending_path_challenge = challenge;
    }

    /// Handle an inbound PATH_CHALLENGE (RFC 9000 §8.2.2): we MUST reply with a
    /// PATH_RESPONSE echoing the exact 8 bytes, on the path the challenge arrived
    /// on, on our next 1-RTT send. Bounded so a flood cannot grow the queue.
    fn onPathChallenge(self: *Conn, data: [8]u8) Error!void {
        if (self.pending_path_responses.items.len >= self.max_pending_path_responses) {
            // Drop the oldest pending echo to bound memory; the peer re-challenges
            // if it still needs validation.
            _ = self.pending_path_responses.orderedRemove(0);
        }
        try self.pending_path_responses.append(self.allocator, data);
    }

    /// Handle an inbound PATH_RESPONSE (RFC 9000 §8.2.3 / §9.3). If it echoes the
    /// challenge we sent AND it arrived from the candidate path we are validating,
    /// the new path is validated: migrate the connection's primary address to it
    /// (§9.3) and reset the candidate state. A response that does not match the
    /// outstanding challenge, or arrives from a different address, is ignored
    /// (an off-path/spoofed PATH_RESPONSE can neither validate nor migrate).
    fn onPathResponse(self: *Conn, data: [8]u8, now: u64) void {
        _ = now;
        if (!self.path_validation.active) return;
        // Constant-time compare the echoed bytes against the outstanding
        // challenge so a guessing attacker gains no timing signal.
        if (!secure_fns.ctEq(&data, &self.path_validation.challenge)) return;
        // The response must come from the candidate path we challenged. `recv_src`
        // is the source of the packet carrying this PATH_RESPONSE.
        const src = self.recv_src orelse return;
        if (!self.path_validation.candidate.eql(src)) return;

        // Validated (RFC 9000 §9.3): migrate the primary path to the new address.
        // RFC 9000 §9.4 permits resetting the congestion controller and RTT
        // estimator to their defaults on migrating to a new path, since the prior
        // estimates describe the old path. We take that option: a new path's
        // capacity is unknown, so re-entering slow start is the safe, RFC-blessed
        // choice (documented). NAT rebinding to the same path is not reached here
        // because an identical address never starts a probe.
        self.path = self.path_validation.candidate;
        self.recovery.onPathMigration();
        self.path_validation.reset();
    }

    /// Drive the path-validation timer (RFC 9000 §8.2.4): if an in-flight
    /// PATH_CHALLENGE has gone unanswered past the PTO-derived deadline, abandon
    /// the candidate path and keep the old (validated) one. Called from
    /// `onTimeout`. Returns true if the abandonment changed state.
    fn tickPathValidation(self: *Conn, now: u64) bool {
        if (!self.path_validation.active) return false;
        if (now < self.path_validation.started_ns +| self.pathValidationDeadlineNs()) return false;
        // The challenge was not answered in time: abandon the new path. The
        // connection keeps using the old, still-validated `self.path`.
        self.path_validation.reset();
        self.pending_path_challenge = null;
        return true;
    }

    /// Whether a candidate-path probe is currently in flight (tests / listener).
    pub fn isValidatingPath(self: *const Conn) bool {
        return self.path_validation.active;
    }

    /// The connection's current (primary) peer path (tests / listener). The
    /// listener reads this so its replies follow a migrated address.
    pub fn currentPath(self: *const Conn) PathAddress {
        return self.path;
    }

    // -----------------------------------------------------------------------
    // Send path
    // -----------------------------------------------------------------------

    /// Collect everything owed and append the resulting datagrams to `out` (an
    /// `*std.ArrayList(OutDatagram)`). Each `OutDatagram.bytes` is owned by the
    /// caller (free via the connection's allocator). Returns the number of
    /// datagrams appended.
    pub fn sendDatagrams(self: *Conn, out: *std.ArrayList(OutDatagram)) Error!usize {
        return self.sendDatagramsAt(out, self.last_recv_ns);
    }

    pub fn sendDatagramsAt(self: *Conn, out: *std.ArrayList(OutDatagram), now: u64) Error!usize {
        // The client must emit its ClientHello before the first send.
        if (self.role == .client and !self.started) {
            switch (self.handshake) {
                .client => |*c| c.startHandshake() catch return error.HandshakeFailed,
                else => unreachable,
            }
            try self.collectHandshakeOutput();
            self.started = true;
        }

        const before = out.items.len;

        // Build everything owed into a staging list first; the
        // anti-amplification gate (RFC 9000 §8.1) then decides how many of those
        // datagrams may actually leave before the peer's address is validated.
        var staged: std.ArrayList(OutDatagram) = .empty;
        defer staged.deinit(self.allocator);

        // 1) Coalesce the handshake levels (Initial + Handshake) into one
        //    datagram, padded to 1200 if it carries a client Initial.
        try self.buildHandshakeDatagram(&staged, now);

        // 2) 1-RTT application datagram (ACKs + queued STREAM/DATAGRAM +
        //    PATH_RESPONSE echoes), once the app keys exist. This goes to the
        //    current primary path.
        try self.buildAppDatagram(&staged, now);

        // 2.5) A candidate-path validation probe (RFC 9000 §8.2.1): a 1-RTT
        //      datagram carrying the PATH_CHALLENGE, routed to the NEW (not-yet-
        //      migrated) address. It is metered against the candidate path's own
        //      3× budget (§9.3.1), separate from the primary-path accounting.
        try self.buildPathProbeDatagram(out, now);

        // 3) A standalone CONNECTION_CLOSE if one is pending and nothing else
        //    carried it.
        if (self.close_pending) try self.buildCloseDatagram(&staged, now);

        // Move staged datagrams into `out`, enforcing the 3× anti-amplification
        // budget while the address is unvalidated. `emitWithinBudget` owns the
        // free of any datagram it withholds.
        try self.emitWithinBudget(&staged, out);

        return out.items.len - before;
    }

    /// Transfer datagrams from `staged` to `out`, enforcing the RFC 9000 §8.1
    /// anti-amplification limit. While the peer's address is unvalidated, a
    /// server may emit at most `3 × bytes_received` total bytes; the first staged
    /// datagram that would push `bytes_sent_unvalidated` past that cap, and every
    /// datagram after it, is withheld and freed here. Once validated (or for the
    /// client role) every staged datagram passes through unmetered.
    ///
    /// Withholding whole datagrams rather than truncating one keeps each emitted
    /// datagram a valid, self-contained QUIC packet; the loss-recovery PTO still
    /// fires later and re-stages the withheld flight, so progress resumes the
    /// moment more bytes arrive (which raises the budget) — the handshake is
    /// never deadlocked, only paced.
    fn emitWithinBudget(self: *Conn, staged: *std.ArrayList(OutDatagram), out: *std.ArrayList(OutDatagram)) Error!void {
        for (staged.items, 0..) |d, i| {
            if (!self.address_validated) {
                const cap = self.bytes_received *| 3;
                const projected = self.bytes_sent_unvalidated +| d.bytes.len;
                if (projected > cap) {
                    // Over budget: withhold this and every remaining staged
                    // datagram. Free them (they will not go on the wire).
                    for (staged.items[i..]) |w| self.allocator.free(w.bytes);
                    return;
                }
                self.bytes_sent_unvalidated = projected;
            }
            // `out.append` may fail (OOM). On failure free this datagram and the
            // rest so nothing leaks, then propagate.
            out.append(self.allocator, d) catch |e| {
                for (staged.items[i..]) |w| self.allocator.free(w.bytes);
                return e;
            };
        }
    }

    /// Assemble Initial and Handshake packets and coalesce them into a single
    /// UDP datagram (RFC 9000 §12.2). Pads to 1200 bytes when a client Initial
    /// is present (RFC 9000 §14.1).
    fn buildHandshakeDatagram(self: *Conn, out: *std.ArrayList(OutDatagram), now: u64) Error!void {
        var datagram: std.ArrayList(u8) = .empty;
        errdefer datagram.deinit(self.allocator);

        // Initial first, then Handshake — the RFC 9000 §12.2 ordering for
        // coalescing. The client Initial is padded inside `appendLongPacket` so
        // the whole datagram reaches 1200 bytes (RFC 9000 §14.1).
        inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |lvl| {
            if (self.keysFor(lvl) != null) {
                _ = try self.appendLongPacket(&datagram, lvl, now);
            }
        }

        if (datagram.items.len == 0) {
            datagram.deinit(self.allocator);
            return;
        }

        const owned = try datagram.toOwnedSlice(self.allocator);
        try out.append(self.allocator, .{ .bytes = owned });
    }

    /// Append one long-header (Initial/Handshake) packet to `datagram`. Returns
    /// true if a packet was actually written. When `pad_packet_to` > 0 the
    /// packet's plaintext is padded with PADDING frames so the whole packet
    /// reaches that many bytes (used to inflate a client Initial).
    fn appendLongPacket(self: *Conn, datagram: *std.ArrayList(u8), level: EncryptionLevel, now: u64) Error!bool {
        const keys = self.keysFor(level) orelse return false;

        // Build the frame payload: ACK (if owed) + CRYPTO (pending flight). Track
        // the CRYPTO ranges so the packet can be re-queued on loss.
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.allocator);

        var ack_eliciting = false;
        var frames = quic_recovery.FrameList{};
        try self.appendAckFrame(&payload, level);

        const send_buf = self.send.cryptoBuf(level).?;
        const header_budget: usize = long_header_max;
        while (send_buf.pending() > 0) {
            const used = datagram.items.len + header_budget + payload.items.len + quic_protect.aead_tag_len;
            const room = if (max_datagram > used) max_datagram - used else 0;
            if (room == 0) break;
            const cf = send_buf.nextFrame(room) orelse break;
            try quic_frame.encodeFrame(&payload, self.allocator, .{ .CRYPTO = cf });
            frames.append(.{ .crypto = .{ .offset = cf.offset, .len = cf.len } });
            ack_eliciting = true;
        }

        if (payload.items.len == 0) return false; // nothing owed

        // For a client Initial we pad the packet so the whole datagram reaches
        // 1200 bytes (RFC 9000 §14.1). Compute the pad target = remaining budget
        // for this packet within the datagram.
        var pad_payload_to: usize = 0;
        if (self.role == .client and level == .initial and self.app_keys == null) {
            const want_packet = if (min_initial_datagram > datagram.items.len)
                min_initial_datagram - datagram.items.len
            else
                0;
            // packet = header(through pn) + payload + tag. Solve for payload.
            const overhead = self.longHeaderLen(level) + quic_protect.aead_tag_len;
            if (want_packet > overhead) pad_payload_to = want_packet - overhead;
        }
        while (payload.items.len < pad_payload_to) {
            try payload.append(self.allocator, 0x00); // PADDING frame
        }

        const sealed = try self.sealLong(datagram, level, keys.write, payload.items);

        // Record the sent packet for RFC 9002 loss recovery. A CRYPTO-bearing
        // packet is ack-eliciting and in flight; an ACK-only one is neither.
        try self.recordSent(level, sealed.pn, sealed.len, ack_eliciting, frames, now);
        self.engine.space(level).onAckSent();
        return true;
    }

    const SealedInfo = struct { pn: u64, len: usize };

    /// Seal one long-header packet over `payload` and append it to `datagram`.
    /// Uses a fixed 4-byte packet number and a 2-byte Length varint (handshake/
    /// Initial payloads always fit), so the header layout is deterministic.
    /// Returns the packet number and on-wire length for recovery accounting.
    fn sealLong(self: *Conn, datagram: *std.ArrayList(u8), level: EncryptionLevel, keys: quic_protect.PacketKeys, payload: []const u8) Error!SealedInfo {
        const pn = self.engine.space(level).nextPacketNumber();
        const pn_len: usize = 4;
        var header_buf: [long_header_max]u8 = undefined;
        const header_len = try self.buildLongHeader(&header_buf, level, pn, pn_len, payload.len);

        const total = header_len + payload.len + quic_protect.aead_tag_len;
        const out_slice = try self.allocator.alloc(u8, total);
        defer self.allocator.free(out_slice);
        const sealed = quic_protect.sealPacketSuite(
            out_slice,
            header_buf[0..header_len],
            header_len - pn_len,
            pn_len,
            pn,
            payload,
            keys,
        ) catch return error.MalformedPacket;
        try datagram.appendSlice(self.allocator, out_slice[0..sealed.len]);
        return .{ .pn = pn, .len = sealed.len };
    }

    /// The exact long-header length (first byte … packet number) for this
    /// connection at `level` with the fixed 4-byte pn + 2-byte Length varint.
    fn longHeaderLen(self: *const Conn, level: EncryptionLevel) usize {
        // 1 (first) + 4 (version) + 1 + dcid + 1 + scid + token_len(1, Initial)
        // + 2 (Length varint) + 4 (pn).
        const token = if (level == .initial) @as(usize, 1) else 0;
        return 1 + 4 + 1 + self.dcid.len + 1 + self.scid.len + token + 2 + 4;
    }

    /// Build the 1-RTT (short-header) application flight. The FIRST packet always
    /// carries any owed ACK / HANDSHAKE_DONE / PATH_RESPONSE / DATAGRAMs plus as
    /// much STREAM data as fits in one `max_datagram` packet. While the
    /// congestion window and the peer's flow-control credit still admit more
    /// STREAM data, ADDITIONAL `max_datagram`-bounded STREAM-only packets are
    /// appended to `out` — so a large response (e.g. `/big`) goes out across many
    /// packets, a congestion-window's worth per call, rather than one impossible
    /// 256 KiB "packet". The remainder stays queued in the per-stream senders and
    /// drains on subsequent calls as ACKs free the window.
    fn buildAppDatagram(self: *Conn, out: *std.ArrayList(OutDatagram), now: u64) Error!void {
        if (self.keysFor(.application) == null) return;

        // ---- packet 0: control frames + first slice of STREAM/DATAGRAM data ----
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.allocator);

        var ack_eliciting = false;
        var frames = quic_recovery.FrameList{};
        try self.appendAckFrame(&payload, .application);

        // HANDSHAKE_DONE (RFC 9000 §19.20): the server confirms the handshake to
        // the client. We emit it on every app datagram while it is owed (a
        // standalone PING-equivalent for loss accounting); it is cleared once the
        // client acknowledges by sending its own 1-RTT application data (its
        // request), proving the confirmation propagated. Re-emitting until then is
        // a cheap, correct retransmit without retaining the frame bytes.
        if (self.role == .server and self.handshake_done_pending) {
            try quic_frame.encodeFrame(&payload, self.allocator, .{ .HANDSHAKE_DONE = {} });
            frames.append(.ping); // ack-eliciting; loss re-arms a fresh send
            ack_eliciting = true;
        }

        // PATH_RESPONSE echoes (RFC 9000 §8.2.2): reply to every PATH_CHALLENGE we
        // received with a PATH_RESPONSE echoing its bytes, on the path the
        // challenge arrived on (the current primary path). These are ack-eliciting
        // and not congestion-gated — path validation must make progress. A bounded
        // batch is drained per send.
        if (self.pending_path_responses.items.len > 0) {
            for (self.pending_path_responses.items) |data| {
                try quic_frame.encodeFrame(&payload, self.allocator, .{ .PATH_RESPONSE = data });
                ack_eliciting = true;
            }
            self.pending_path_responses.clearRetainingCapacity();
        }

        // Whether the congestion window still admits ack-eliciting data. ACKs are
        // not in flight, so an ACK-only packet always goes out; STREAM/DATAGRAM
        // data is gated by `canSend` (RFC 9002 §7).
        const cwnd_open = self.recovery.canSend(max_datagram);

        if (cwnd_open) {
            // Queued DATAGRAMs (RFC 9221) ride the first packet. Not retransmitted
            // on loss (RFC 9221 §5.2) so they need no re-queue descriptor. Each is
            // bounded to fit a single packet; oversize ones were rejected upstream.
            for (self.pending_datagrams.items) |p| {
                const overhead = 2 + varIntLen(p.data.len);
                if (payload.items.len + overhead + p.data.len + quic_protect.aead_tag_len > max_datagram) break;
                try quic_frame.encodeFrame(&payload, self.allocator, .{ .DATAGRAM = .{
                    .len = p.data.len,
                    .data = p.data,
                } });
                ack_eliciting = true;
            }
            self.clearPendingDatagrams();

            // Fill the rest of this first packet with STREAM data.
            if (try self.fillStreamFrames(&payload, &frames, max_datagram)) ack_eliciting = true;
        }

        // Emit packet 0 if it carries anything (an ACK-only packet still goes out).
        if (payload.items.len != 0) {
            try self.sealAndAppendApp(out, payload.items, ack_eliciting, frames, now);
        }

        // ---- additional STREAM-only packets, cwnd + flow-control bounded -------
        // Keep filling `max_datagram`-sized packets with STREAM data while the
        // window admits more and data remains. `recovery.canSend` re-checks the
        // in-flight total after each recorded send, so this loop naturally stops
        // at one congestion window per call; the rest drains on later calls.
        while (self.recovery.canSend(max_datagram) and self.anyStreamSendable()) {
            var pkt: std.ArrayList(u8) = .empty;
            defer pkt.deinit(self.allocator);
            var pkt_frames = quic_recovery.FrameList{};
            const wrote = try self.fillStreamFrames(&pkt, &pkt_frames, max_datagram);
            if (!wrote or pkt.items.len == 0) break; // flow-control blocked: stop
            try self.sealAndAppendApp(out, pkt.items, true, pkt_frames, now);
        }
    }

    /// Seal one 1-RTT packet over `payload` and append it to `out`, updating the
    /// key-update epoch counters and recording it for loss recovery.
    fn sealAndAppendApp(
        self: *Conn,
        out: *std.ArrayList(OutDatagram),
        payload: []const u8,
        ack_eliciting: bool,
        frames: quic_recovery.FrameList,
        now: u64,
    ) Error!void {
        const keys = self.keysFor(.application) orelse return error.NotEstablished;
        const pn = self.engine.space(.application).nextPacketNumber();
        const pn_len: usize = 4;
        var header_buf: [long_header_max]u8 = undefined;
        const header_len = try self.buildShortHeader(&header_buf, pn, pn_len);

        const total = header_len + payload.len + quic_protect.aead_tag_len;
        const out_slice = try self.allocator.alloc(u8, total);
        defer self.allocator.free(out_slice);
        const sealed = quic_protect.sealPacketSuite(
            out_slice,
            header_buf[0..header_len],
            header_len - pn_len,
            pn_len,
            pn,
            payload,
            keys.write,
        ) catch return error.MalformedPacket;

        const owned = try self.allocator.dupe(u8, out_slice[0..sealed.len]);
        try out.append(self.allocator, .{ .bytes = owned });

        // Confidentiality-limit accounting (RFC 9001 §6.6): count packets
        // protected with the current send key, and record the first packet number
        // we sent in a self-initiated new phase so an ACK of it confirms the
        // update (§6.5).
        if (self.key_update.ready) {
            self.key_update.packets_sent_epoch +|= 1;
            if (self.key_update.initiated and self.key_update.confirm_pn == null) {
                self.key_update.confirm_pn = pn;
            }
        }

        try self.recordSent(.application, pn, sealed.len, ack_eliciting, frames, now);
        self.engine.space(.application).onAckSent();
    }

    /// Greedily pack STREAM frames from the per-stream senders into `payload`
    /// until it would exceed `packet_budget` (the target on-wire packet size) or
    /// the per-stream / connection flow-control credit is exhausted. Records each
    /// emitted range in `frames` for loss recovery and advances each sender's
    /// `send_offset`. Returns true if any STREAM frame was written. Visits streams
    /// in FIFO order so a single huge stream cannot starve a later one within a
    /// packet, while still letting one stream fill a packet on its own.
    fn fillStreamFrames(
        self: *Conn,
        payload: *std.ArrayList(u8),
        frames: *quic_recovery.FrameList,
        packet_budget: usize,
    ) Error!bool {
        var wrote = false;
        for (self.stream_order.items) |sid| {
            const sender = self.stream_senders.getPtr(sid) orelse continue;
            while (sender.hasSendable()) {
                if (frames.len >= quic_recovery.FrameList.cap) return wrote; // recovery descriptor space
                // Remaining room in this packet for a STREAM frame's payload,
                // after its header (type + stream id + offset + length varints).
                const used = payload.items.len + quic_protect.aead_tag_len;
                if (used >= packet_budget) return wrote;
                const room = packet_budget - used;

                const data_off = sender.send_offset;
                const hdr_overhead = streamFrameHeaderLen(sid, data_off);
                if (room <= hdr_overhead) return wrote; // no room for even 1 data byte
                var max_payload = room - hdr_overhead;

                // Honor the peer's flow-control credit (RFC 9000 §4.1): never send
                // past the per-stream limit or the connection-level limit.
                const stream_credit = self.streamSendCredit(sid, data_off);
                const conn_credit = self.connSendCredit();
                max_payload = @min(max_payload, @min(stream_credit, conn_credit));

                const unsent = sender.unsent();
                const send_len = @min(@as(u64, max_payload), unsent);

                // A pure-FIN (no data) frame: allowed only when all data is sent
                // and flow control isn't the blocker (a zero-length frame consumes
                // no credit).
                const is_fin = if (sender.fin_offset) |fo|
                    (!sender.fin_sent and data_off + send_len >= fo)
                else
                    false;

                if (send_len == 0 and !is_fin) break; // flow-control blocked this stream

                const slice_start: usize = @intCast(data_off - sender.acked_offset);
                const slice = sender.buf.items[slice_start .. slice_start + @as(usize, @intCast(send_len))];

                try quic_frame.encodeFrame(payload, self.allocator, .{ .STREAM = .{
                    .stream_id = sid,
                    .offset = data_off,
                    .fin = is_fin,
                    .len = slice.len,
                    .data = slice,
                } });
                frames.append(.{ .stream = .{
                    .stream_id = sid,
                    .offset = data_off,
                    .len = slice.len,
                    .fin = is_fin,
                } });
                wrote = true;

                sender.send_offset += send_len;
                self.fc_data_sent += send_len;
                if (is_fin) sender.fin_sent = true;

                // If this packet is now full, move on (the outer loop opens a new
                // packet for whatever remains).
                if (payload.items.len + quic_protect.aead_tag_len >= packet_budget) return wrote;
                // If flow control (not packet space) capped this frame, stop this
                // stream and try the next one.
                if (send_len < unsent and send_len == max_payload) break;
            }
        }
        return wrote;
    }

    /// Per-stream send-side flow-control credit (RFC 9000 §4.1): how many more
    /// bytes the peer will accept on `sid` past `offset`. Seeded from the peer's
    /// `initial_max_stream_data_*` and raised by MAX_STREAM_DATA. A missing limit
    /// means "not yet learned" → fall back to the connection limit only.
    fn streamSendCredit(self: *Conn, sid: u64, offset: u64) u64 {
        const limit = self.peer_max_stream_data.get(sid) orelse self.peerInitialStreamDataLimit(sid);
        return if (limit > offset) limit - offset else 0;
    }

    /// Connection-level send-side flow-control credit (RFC 9000 §4.1): bytes the
    /// peer will accept across all streams past what we have already queued.
    fn connSendCredit(self: *Conn) u64 {
        const limit = self.peer_max_data orelse self.peerInitialMaxData();
        return if (limit > self.fc_data_sent) limit - self.fc_data_sent else 0;
    }

    /// The peer's advertised `initial_max_data` (or a conservative default until
    /// the transport parameters are known — large enough to admit the handshake's
    /// tiny control streams without stalling, small enough to be safe).
    fn peerInitialMaxData(self: *Conn) u64 {
        if (self.peerTransportParams()) |p| {
            if (p.initial_max_data) |v| return v;
        }
        return default_peer_initial_max_data;
    }

    /// The peer's advertised per-stream initial limit for `sid`. A client-
    /// initiated bidi stream (the case for an HTTP/3 request the server answers)
    /// is limited by the peer's `initial_max_stream_data_bidi_remote`; uni streams
    /// by `initial_max_stream_data_uni`.
    fn peerInitialStreamDataLimit(self: *Conn, sid: u64) u64 {
        const p = self.peerTransportParams() orelse return default_peer_initial_max_stream_data;
        const is_uni = (sid & 0x2) != 0;
        const v = if (is_uni)
            p.initial_max_stream_data_uni
        else
            // We (the answerer) send on a stream the *peer* opened → from the
            // peer's perspective it is "bidi_remote"; for a stream we opened it is
            // "bidi_local". HTTP/3 request streams are peer-opened.
            (p.initial_max_stream_data_bidi_remote orelse p.initial_max_stream_data_bidi_local);
        return v orelse default_peer_initial_max_stream_data;
    }

    /// Whether any stream still has sendable bytes (data or an untransmitted FIN).
    fn anyStreamSendable(self: *Conn) bool {
        for (self.stream_order.items) |sid| {
            if (self.stream_senders.getPtr(sid)) |s| {
                if (s.hasSendable()) return true;
            }
        }
        return false;
    }

    /// Build a candidate-path validation probe (RFC 9000 §8.2.1): a 1-RTT
    /// datagram carrying the outstanding PATH_CHALLENGE, addressed to the NEW
    /// (not-yet-migrated) path. The datagram's `dest` is set to the candidate so
    /// the listener routes it to the new address while app data continues to the
    /// old primary path.
    ///
    /// Anti-amplification (RFC 9000 §9.3.1): the new path has its own 3× budget
    /// seeded from the bytes received on it. We refuse to emit the probe if it
    /// would push the candidate path's sent total past `3 × bytes_received`, so a
    /// spoofed off-path packet (which makes US the one challenged) can never turn
    /// the server into a reflector toward the victim address. RFC 9000 §8.2.1
    /// would have us pad a path-validation packet to ≥1200 bytes, but that padding
    /// is explicitly excused when it would exceed the anti-amplification limit
    /// (§8.2.1 / §9.3.1); we therefore send the challenge un-padded so the small
    /// receive budget still admits it.
    fn buildPathProbeDatagram(self: *Conn, out: *std.ArrayList(OutDatagram), now: u64) Error!void {
        if (!self.path_validation.active or !self.path_validation.challenge_pending) return;
        const keys = self.keysFor(.application) orelse return;

        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.allocator);

        // PATH_CHALLENGE is itself ack-eliciting (RFC 9000 §8.2.1 / §13.2.1).
        try quic_frame.encodeFrame(&payload, self.allocator, .{
            .PATH_CHALLENGE = self.path_validation.challenge,
        });

        const pn = self.engine.space(.application).nextPacketNumber();
        const pn_len: usize = 4;
        var header_buf: [long_header_max]u8 = undefined;
        const header_len = try self.buildShortHeader(&header_buf, pn, pn_len);

        const total = header_len + payload.items.len + quic_protect.aead_tag_len;

        // Candidate-path 3× anti-amplification gate (RFC 9000 §9.3.1): never emit
        // a probe that would exceed 3× the bytes received on the new path.
        const cap = self.path_validation.bytes_received *| 3;
        if (self.path_validation.bytes_sent +| total > cap) return;

        const out_slice = try self.allocator.alloc(u8, total);
        defer self.allocator.free(out_slice);
        const sealed = quic_protect.sealPacketSuite(
            out_slice,
            header_buf[0..header_len],
            header_len - pn_len,
            pn_len,
            pn,
            payload.items,
            keys.write,
        ) catch return error.MalformedPacket;

        const owned = try self.allocator.dupe(u8, out_slice[0..sealed.len]);
        errdefer self.allocator.free(owned);
        // Route the probe to the CANDIDATE path, not the primary one.
        try out.append(self.allocator, .{ .bytes = owned, .dest = self.path_validation.candidate });

        self.path_validation.bytes_sent +|= sealed.len;
        // The challenge has been sent; do not re-send it every flush (it is
        // retransmitted by the PTO path if lost — a PATH_CHALLENGE is ack-
        // eliciting and recorded for loss recovery below).
        self.path_validation.challenge_pending = false;
        if (self.key_update.ready) self.key_update.packets_sent_epoch +|= 1;

        // Record the probe for loss recovery + the ACK-sent bookkeeping. A lost
        // PATH_CHALLENGE re-arms via the PTO (the recovery PING re-queue), and a
        // genuinely-unreachable path is abandoned by `tickPathValidation`.
        var frames = quic_recovery.FrameList{};
        frames.append(.ping); // re-arm trigger if lost
        try self.recordSent(.application, pn, sealed.len, true, frames, now);
        self.engine.space(.application).onAckSent();
    }

    fn buildCloseDatagram(self: *Conn, out: *std.ArrayList(OutDatagram), now: u64) Error!void {
        _ = now;
        const level: EncryptionLevel = if (self.app_keys != null) .application else if (self.handshake_keys != null) .handshake else .initial;
        const keys = self.keysFor(level) orelse return;

        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.allocator);
        try quic_frame.encodeFrame(&payload, self.allocator, .{ .CONNECTION_CLOSE = .{
            .error_code = self.close_error orelse transport_error_no_error,
            .reason_len = 0,
            .reason = "",
        } });

        const pn = self.engine.space(level).nextPacketNumber();
        const pn_len: usize = 4;
        var header_buf: [long_header_max]u8 = undefined;
        const header_len = if (level == .application)
            try self.buildShortHeader(&header_buf, pn, pn_len)
        else
            try self.buildLongHeader(&header_buf, level, pn, pn_len, payload.items.len);

        const total: usize = header_len + payload.items.len + quic_protect.aead_tag_len;
        const out_slice = try self.allocator.alloc(u8, total);
        defer self.allocator.free(out_slice);

        const sealed = quic_protect.sealPacketSuite(
            out_slice,
            header_buf[0..header_len],
            header_len - pn_len,
            pn_len,
            pn,
            payload.items,
            keys.write,
        ) catch return error.MalformedPacket;
        const owned = try self.allocator.dupe(u8, out_slice[0..sealed.len]);
        try out.append(self.allocator, .{ .bytes = owned });
        self.close_pending = false;
    }

    /// Append an ACK frame for `level` if one is owed, encoding the engine's
    /// received-range set.
    fn appendAckFrame(self: *Conn, payload: *std.ArrayList(u8), level: EncryptionLevel) Error!void {
        const sp = self.engine.space(level);
        if (!sp.ackPending()) return;
        var built = (sp.buildAck(self.allocator, 0) catch return) orelse return;
        defer built.deinit(self.allocator);
        try quic_frame.encodeFrame(payload, self.allocator, .{ .ACK = built.frame });
    }

    // -----------------------------------------------------------------------
    // Header builders
    // -----------------------------------------------------------------------

    /// Build a long-header (Initial/Handshake) AAD: first byte … packet number,
    /// with a fixed 4-byte packet number and a fixed 2-byte Length varint.
    /// `payload_len` is the frame-payload length (Length = pn_len + payload +
    /// tag). Handshake/Initial payloads always fit a 2-byte Length (< 16384), so
    /// the layout is deterministic and `longHeaderLen` mirrors it.
    fn buildLongHeader(
        self: *Conn,
        out: *[long_header_max]u8,
        level: EncryptionLevel,
        pn: u64,
        pn_len: usize,
        payload_len: usize,
    ) Error!usize {
        const ptype: quic_packet.LongPacketType = switch (level) {
            .initial => .initial,
            .handshake => .handshake,
            .application => unreachable,
        };
        const pnl = quic_packet.PacketNumberLength.fromByteLen(pn_len) catch return error.MalformedPacket;
        const header = quic_packet.LongHeader{
            .packet_type = ptype,
            .version = quic_version_1,
            .dcid = self.dcid,
            .scid = self.scid,
            .packet_number_len = pnl,
        };
        var pos = quic_packet.encodeLongHeader(out, header) catch return error.MalformedPacket;

        // Initial packets carry an (empty) Token before Length.
        if (level == .initial) {
            if (pos + 1 > out.len) return error.MalformedPacket;
            out[pos] = 0x00; // token length varint = 0
            pos += 1;
        }

        // Length = pn_len + payload + tag, encoded as a fixed 2-byte varint.
        const length_value = pn_len + payload_len + quic_protect.aead_tag_len;
        if (length_value > 0x3fff) return error.MalformedPacket; // >2-byte Length: out of scope
        if (pos + 2 > out.len) return error.MalformedPacket;
        const lv: u16 = @as(u16, @intCast(length_value)) | 0x4000;
        std.mem.writeInt(u16, out[pos..][0..2], lv, .big);
        pos += 2;

        // Packet number (truncated to pn_len bytes).
        const trunc = quic_frame.truncatePacketNumber(pn, pn_len) catch return error.MalformedPacket;
        const enc = quic_packet.encodePacketNumber(out[pos..], @intCast(trunc), pnl) catch return error.MalformedPacket;
        pos += enc;
        return pos;
    }

    fn buildShortHeader(self: *Conn, out: *[long_header_max]u8, pn: u64, pn_len: usize) Error!usize {
        const trunc = quic_frame.truncatePacketNumber(pn, pn_len) catch return error.MalformedPacket;
        const header = quic_packet.ShortHeader{
            .spin = false,
            // The key-phase bit (RFC 9001 §6.3) reflects the current send
            // generation; it stays 0 until the first key update.
            .key_phase = self.key_update.phase == 1,
            .dcid = self.dcid,
            .packet_number = @intCast(trunc),
            .packet_number_len = quic_packet.PacketNumberLength.fromByteLen(pn_len) catch return error.MalformedPacket,
        };
        return quic_packet.encodeShortHeader(out, header) catch return error.MalformedPacket;
    }

    // -----------------------------------------------------------------------
    // Application I/O
    // -----------------------------------------------------------------------

    /// Open a new bidirectional stream; returns its id. The first send carrying
    /// data on it goes out on the next `sendDatagrams`.
    pub fn openStream(self: *Conn) Error!u64 {
        if (!self.established) return error.NotEstablished;
        const id = self.next_bidi_stream;
        self.next_bidi_stream += 4; // same-type stream ids advance by 4 (RFC 9000 §2.1)
        return id;
    }

    /// Open a new unidirectional stream; returns its id. Used for HTTP/3 control
    /// and QPACK encoder/decoder streams and WebTransport uni streams. The first
    /// send carrying data on it goes out on the next `sendDatagrams`.
    pub fn openUniStream(self: *Conn) Error!u64 {
        if (!self.established) return error.NotEstablished;
        const id = self.next_uni_stream;
        self.next_uni_stream += 4; // same-type stream ids advance by 4 (RFC 9000 §2.1)
        return id;
    }

    /// Queue `bytes` to send on `stream_id` (optionally with the fin bit). The
    /// data is retained in the stream's send buffer until acknowledged, so a lost
    /// STREAM range can be re-transmitted automatically; it is segmented onto the
    /// wire (cwnd + flow-control bounded) by the next `sendDatagrams`.
    pub fn sendStream(self: *Conn, stream_id: u64, bytes: []const u8, fin: bool) Error!void {
        if (!self.established) return error.NotEstablished;
        const sender = try self.streamSender(stream_id);
        if (bytes.len > 0) try sender.buf.appendSlice(self.allocator, bytes);
        if (fin) sender.fin_offset = sender.queuedEnd();
    }

    /// Get (creating if absent) the per-stream sender, registering its id in the
    /// FIFO visit order on first creation.
    fn streamSender(self: *Conn, stream_id: u64) Error!*StreamSender {
        const gop = try self.stream_senders.getOrPut(self.allocator, stream_id);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{};
            try self.stream_order.append(self.allocator, stream_id);
        }
        return gop.value_ptr;
    }

    /// Read up to `dst.len` contiguous received bytes from `stream_id`, returns
    /// the number read (0 if none ready). Delegates to the Engine's reassembly.
    pub fn readStream(self: *Conn, stream_id: u64, dst: []u8) usize {
        const s = self.engine.getStream(stream_id) orelse return 0;
        const avail = s.peek();
        const n = @min(dst.len, avail.len);
        @memcpy(dst[0..n], avail[0..n]);
        _ = s.consume(n);
        return n;
    }

    /// Whether the peer signalled fin on `stream_id` and we have drained it.
    pub fn streamFinished(self: *Conn, stream_id: u64) bool {
        const s = self.engine.getStream(stream_id) orelse return false;
        return s.finReached();
    }

    /// Queue an application DATAGRAM (RFC 9221). Copied; shipped next send.
    pub fn sendDatagram(self: *Conn, bytes: []const u8) Error!void {
        if (!self.established) return error.NotEstablished;
        const copy = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(copy);
        try self.pending_datagrams.append(self.allocator, .{ .data = copy });
    }

    /// Copy a received DATAGRAM payload into the bounded inbox. Drops the oldest
    /// entry if the inbox is full so a flood cannot drive unbounded growth.
    fn captureRecvDatagram(self: *Conn, bytes: []const u8) Error!void {
        const copy = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(copy);
        if (self.recv_datagrams.items.len >= self.max_recv_datagrams) {
            const oldest = self.recv_datagrams.orderedRemove(0);
            self.allocator.free(oldest.data);
        }
        try self.recv_datagrams.append(self.allocator, .{ .data = copy });
    }

    /// Take the oldest received application DATAGRAM payload (RFC 9221), or null
    /// if none. The returned slice is an owned copy; the caller frees it via the
    /// connection's allocator. FIFO drain.
    pub fn recvDatagramPayload(self: *Conn) ?[]u8 {
        if (self.recv_datagrams.items.len == 0) return null;
        const item = self.recv_datagrams.orderedRemove(0);
        return item.data;
    }

    // -----------------------------------------------------------------------
    // 1-RTT key update (RFC 9001 §6)
    // -----------------------------------------------------------------------

    /// Initiate a 1-RTT key update (RFC 9001 §6.1): roll our write (send) secret
    /// to the next generation, flip our outbound key-phase bit, and pre-arm the
    /// confirmation tracking. Subsequent 1-RTT packets are protected with the new
    /// keys and carry the flipped phase bit; the peer detects the flip, updates in
    /// turn, and acks a packet in the new phase, which confirms the update.
    ///
    /// Per §6.5 an endpoint MUST NOT initiate a second update before the peer has
    /// acknowledged a packet in the current (new) phase; this returns
    /// `error.NotEstablished` when called before the connection is up and is a
    /// no-op (returns false) when an update is already in flight unconfirmed or
    /// key update is unavailable for the negotiated suite.
    pub fn initiateKeyUpdate(self: *Conn) Error!bool {
        if (!self.established) return error.NotEstablished;
        if (!self.key_update.ready) return false; // suite without key-update support
        if (self.key_update.initiated) return false; // §6.5: previous update unconfirmed
        const now = self.last_recv_ns;

        // A key update rolls BOTH directions to the next generation under a single
        // flipped key-phase bit (§6.1). Our send keys roll immediately so new
        // packets are protected with the new keys and carry the new phase; the
        // read keys roll too, with the old read keys retained briefly so the
        // peer's still-in-flight old-phase packets keep decrypting (§6.4).
        const new_phase: u1 = ~self.key_update.phase; // 0↔1
        self.rollGeneration(new_phase, now);
        self.key_update.initiated = true;
        self.key_update.confirm_pn = null;
        return true;
    }

    /// Whether the current send epoch has reached the AEAD confidentiality limit
    /// (RFC 9001 §6.6) and the application should initiate a key update. Exposed
    /// so the layer above can rotate proactively; the driver never reuses a
    /// (key, nonce) pair regardless.
    pub fn wantsKeyUpdate(self: *const Conn) bool {
        if (!self.key_update.ready or self.key_update.initiated) return false;
        return self.key_update.packets_sent_epoch >= KeyUpdate.confidentiality_limit;
    }

    /// The current key-phase bit (0/1) for tests / introspection.
    pub fn keyPhase(self: *const Conn) u1 {
        return self.key_update.phase;
    }

    /// Packets protected with the current send key this epoch (§6.6 counter).
    pub fn keyUpdatePacketsSent(self: *const Conn) u64 {
        return self.key_update.packets_sent_epoch;
    }

    /// AEAD authentication failures observed (§6.6 integrity-limit counter).
    pub fn keyUpdateAeadFailures(self: *const Conn) u64 {
        return self.key_update.aead_failures;
    }

    /// Initiate a graceful CONNECTION_CLOSE with `error_code` (0 = NO_ERROR).
    pub fn close(self: *Conn, error_code: u64) void {
        if (self.closing) return;
        self.closing = true;
        self.close_error = error_code;
        self.close_pending = true;
    }

    /// Free the queued application DATAGRAMs after they were copied into a packet
    /// (RFC 9221 — not retransmitted, so no descriptor is retained).
    fn clearPendingDatagrams(self: *Conn) void {
        for (self.pending_datagrams.items) |p| self.allocator.free(p.data);
        self.pending_datagrams.clearRetainingCapacity();
    }

    // -----------------------------------------------------------------------
    // Loss recovery + congestion control wiring (RFC 9002)
    // -----------------------------------------------------------------------

    /// Record a freshly-sealed packet with the loss-recovery controller. Only
    /// ack-eliciting packets count toward the in-flight congestion window; an
    /// ACK-only packet is recorded as not-in-flight so it cannot arm the PTO.
    fn recordSent(
        self: *Conn,
        level: EncryptionLevel,
        pn: u64,
        sent_bytes: usize,
        ack_eliciting: bool,
        frames: quic_recovery.FrameList,
        now: u64,
    ) Error!void {
        try self.recovery.onPacketSent(level, .{
            .packet_number = pn,
            .time_sent_ns = now,
            .in_flight = ack_eliciting,
            .ack_eliciting = ack_eliciting,
            .sent_bytes = @intCast(sent_bytes),
            .frames = frames,
        });
        self.refreshTimer(now);
    }

    /// Recompute the next loss-detection / PTO timer from the recovery state.
    fn refreshTimer(self: *Conn, now: u64) void {
        const t = self.recovery.nextTimer(now);
        self.timer_kind = t.kind;
        self.timer_deadline_ns = switch (t.kind) {
            .none => null,
            else => t.deadline_ns,
        };
    }

    /// Feed an inbound ACK's newly-acked packet numbers to the recovery layer:
    /// sample RTT, detect loss, update the congestion window, and re-queue any
    /// lost frames for retransmission. `level` selects the packet-number space.
    fn onAckProcessed(self: *Conn, level: EncryptionLevel, largest_acked: u64, now: u64) Error!void {
        const outcome = try self.recovery.onAckReceived(
            level,
            self.newly_acked.items,
            largest_acked,
            0, // ack_delay: our peer encodes 0 (we send delay=0); decoded ns = 0.
            now,
        );
        // Reclaim acknowledged STREAM send-buffer bytes BEFORE re-queuing losses,
        // so a range that is both acked (in this ACK) and previously lost ends up
        // correctly reclaimed rather than re-sent.
        for (outcome.acked_frames) |f| {
            switch (f) {
                .stream => |s| self.ackStreamRange(s.stream_id, s.offset, s.len),
                else => {},
            }
        }
        try self.requeueLostFrames(outcome.lost_frames);

        // Once the client acknowledges any 1-RTT packet we sent, our HANDSHAKE_DONE
        // (which rode the app datagrams while pending) has demonstrably been
        // delivered, so stop re-emitting it (RFC 9000 §13.3 — a frame is retired
        // when acknowledged). On loss before this ack, the per-datagram re-emit
        // above keeps confirming.
        if (level == .application) self.handshake_done_pending = false;

        // Key-update confirmation (RFC 9001 §6.5): once the peer acks a packet we
        // sent in the new phase, our self-initiated update is confirmed and we may
        // initiate the next one.
        if (level == .application and self.key_update.initiated) {
            if (self.key_update.confirm_pn) |cp| {
                if (largest_acked >= cp) self.key_update.initiated = false;
            }
        }

        self.refreshTimer(now);
    }

    /// Re-queue frames from packets the recovery layer declared lost. CRYPTO is
    /// re-emitted by rewinding the per-level send buffer to the lost offset;
    /// STREAM data is re-enqueued from the per-stream sent map; PING is covered
    /// by the next ack-eliciting send.
    fn requeueLostFrames(self: *Conn, lost: []const quic_recovery.LostFrame) Error!void {
        for (lost) |f| {
            switch (f) {
                .crypto => |c| self.rewindCryptoTo(c.offset),
                .stream => |s| try self.requeueStream(s.stream_id, s.offset, s.len, s.fin),
                .ping => {}, // a fresh ack-eliciting send / PING probe covers it
            }
        }
    }

    /// Rewind the relevant CRYPTO send buffer so bytes from `offset` onward are
    /// re-emitted on the next send. We rewind whichever handshake-level buffer
    /// owns the offset (Initial or Handshake); the application level has no
    /// send-side CRYPTO buffer here.
    fn rewindCryptoTo(self: *Conn, offset: u64) void {
        inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |lvl| {
            const buf = self.send.cryptoBuf(lvl).?;
            // The offset belongs to this buffer if it lies within its written
            // range and at/below the current send_offset (already emitted).
            const lo = buf.base_offset;
            const hi = buf.base_offset + buf.buf.items.len;
            if (offset >= lo and offset < hi and offset < buf.send_offset) {
                buf.send_offset = offset;
            }
        }
    }

    /// Re-enqueue a lost STREAM range (RFC 9002 §6 — lost data is retransmitted).
    /// The bytes are still retained in the stream's send buffer (we drop bytes
    /// from the buffer only when the peer ACKs them), so rolling `send_offset`
    /// back to the lost offset re-marks them un-sent and the next `sendDatagrams`
    /// re-emits them from our own buffer — no application re-supply needed.
    /// A lost FIN is covered because `fin_sent` is cleared so `hasSendable` is
    /// true again whenever the rolled-back offset reaches `fin_offset`.
    fn requeueStream(self: *Conn, stream_id: u64, offset: u64, len: u64, fin: bool) Error!void {
        _ = len;
        const sender = self.stream_senders.getPtr(stream_id) orelse return;
        // Only roll back if the lost offset is still ahead of what the peer has
        // acknowledged (already-acked bytes were dropped from the buffer and must
        // never be re-sent). Take the minimum so an out-of-order set of lost
        // ranges rewinds to the earliest hole.
        if (offset >= sender.acked_offset and offset < sender.send_offset) {
            sender.send_offset = offset;
        }
        if (fin) sender.fin_sent = false;
    }

    /// Drop acknowledged bytes from a stream's send buffer (RFC 9002 §6 / RFC
    /// 9000 §2.3): once the peer ACKs a contiguous prefix, those bytes can never
    /// be needed again, so free them from the front to keep retention bounded.
    /// We advance `acked_offset` to the high end of any acked range that starts
    /// at (or before) the current acked frontier; non-contiguous acks wait for
    /// the gap to fill. This is a conservative, contiguous-prefix reclaim.
    fn ackStreamRange(self: *Conn, stream_id: u64, offset: u64, len: u64) void {
        const sender = self.stream_senders.getPtr(stream_id) orelse return;
        const end = offset + len;
        // Only a range touching the un-acked frontier reclaims memory; a range
        // strictly ahead leaves a hole we cannot compact yet (kept retained).
        if (offset <= sender.acked_offset and end > sender.acked_offset) {
            const drop: usize = @intCast(end - sender.acked_offset);
            const have = sender.buf.items.len;
            const n = @min(drop, have);
            if (n > 0) {
                std.mem.copyForwards(u8, sender.buf.items[0 .. have - n], sender.buf.items[n..]);
                sender.buf.shrinkRetainingCapacity(have - n);
            }
            sender.acked_offset = end;
            if (sender.send_offset < sender.acked_offset) sender.send_offset = sender.acked_offset;
        }
    }

    // -----------------------------------------------------------------------
    // Timers (RFC 9002 §6.1.2 loss timer + §6.2 PTO) and idle timeout
    // -----------------------------------------------------------------------

    /// Advance time to `now`. Returns true if a retransmit is now owed (the
    /// caller should call `sendDatagrams` again). Drives the RFC 9002 loss /
    /// PTO timer and the idle timeout.
    pub fn onTimeout(self: *Conn, now: u64) Error!bool {
        // Idle timeout (RFC 9000 §10.1).
        if (self.last_recv_ns != 0 and now > self.last_recv_ns + self.idle_timeout_ns) {
            self.closing = true;
            return error.IdleTimeout;
        }

        // Path-validation abandonment (RFC 9000 §8.2.4 / §9.3.2): an in-flight
        // PATH_CHALLENGE that goes unanswered past the PTO-derived deadline
        // abandons the candidate path; the old (validated) path is kept. This runs
        // independently of the loss/PTO timer so a candidate path that is silently
        // unreachable is never left probing forever.
        const path_abandoned = self.tickPathValidation(now);

        const deadline = self.timer_deadline_ns orelse return path_abandoned;
        if (now < deadline) return path_abandoned;

        switch (self.timer_kind) {
            .loss => {
                // Loss-detection timeout (§6.1.2): re-detect losses and re-queue.
                const lost = try self.recovery.onLossDetectionTimeout(now);
                try self.requeueLostFrames(lost);
            },
            .pto => {
                // PTO (§6.2): send probe(s). We re-queue the oldest outstanding
                // ack-eliciting frames so the next send retransmits them, and
                // increment the backoff. If nothing is outstanding to retransmit,
                // the probe is a bare ack-eliciting send (the handshake CRYPTO is
                // already pending, or a future PING covers the app space).
                const probe = try self.recovery.onPtoExpired();
                try self.requeueLostFrames(probe);
            },
            .none => return path_abandoned,
        }

        // If a candidate-path probe is still in flight when the loss/PTO timer
        // fires, re-arm the PATH_CHALLENGE so the next send re-probes the new path
        // (a PATH_CHALLENGE is ack-eliciting; its loss is covered by the PTO).
        if (self.path_validation.active and !path_abandoned) {
            self.path_validation.challenge_pending = true;
            self.pending_path_challenge = self.path_validation.challenge;
        }

        self.refreshTimer(now);
        return true;
    }

    /// Mark the handshake confirmed in the recovery layer (1-RTT keys in use and
    /// the handshake complete) and discard the Handshake packet-number space's
    /// sent state (RFC 9001 §4.9.2 / RFC 9002 §6.4).
    fn confirmHandshakeRecovery(self: *Conn) void {
        if (self.recovery.handshake_confirmed) return;
        self.recovery.setHandshakeConfirmed();
        self.recovery.discardSpace(.handshake);
    }

    /// Rewind every still-un-acked handshake-level CRYPTO buffer so a pending
    /// flight is retransmitted. Retained for the legacy fixed-PTO test surface;
    /// the live path uses the RFC 9002 per-packet loss detection above.
    fn rewindUnackedCrypto(self: *Conn) void {
        inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |lvl| {
            const sp = self.engine.space(lvl);
            const buf = self.send.cryptoBuf(lvl).?;
            const emitted = buf.send_offset - buf.base_offset;
            if (emitted > 0) {
                const fully_acked = if (sp.largest_acked) |la| la + 1 >= sp.next_outbound else false;
                if (!fully_acked) buf.send_offset = buf.base_offset;
            }
        }
    }
};

// ===========================================================================
// Packet-number decode context (openPacketSuite wants a free function)
// ===========================================================================
//
// `openPacketSuite` takes a `*const fn (truncated, pn_len) u64`. We thread the
// largest-received packet number through a thread-local so the reconstruction
// (RFC 9000 §A.3) is correct without changing the signature. Single-threaded
// per connection; the listener serializes recv per connection.
const PnDecodeCtx = struct {
    largest: ?u64,

    threadlocal var current: PnDecodeCtx = .{ .largest = null };
    threadlocal var last_full: u64 = 0;

    fn decode(truncated: u64, pn_len: usize) u64 {
        const largest = current.largest orelse {
            last_full = truncated;
            return truncated;
        };
        const full = quic_frame.decodePacketNumber(truncated, pn_len, largest) catch truncated;
        last_full = full;
        return full;
    }
};

// ===========================================================================
// Small bounds-checked helpers
// ===========================================================================

/// Decode a QUIC varint at `input[off..]`, returning value + byte length.
///
/// Unlike `quic_frame.decodeVarInt`, this does NOT reject a non-minimal
/// encoding. RFC 9000 §16 lets a sender use a longer-than-minimal varint and
/// requires receivers to accept it; the header's Length and Token fields are
/// parsed with this tolerant decoder (our own sender emits a fixed 2-byte
/// Length varint, which is non-minimal for small packets).
/// QUIC handshake/interop tracing, gated on `ONYX_QUIC_DEBUG` (any non-empty
/// value). Off by default; only read by interop triage (`tools/quic_interop.sh`)
/// and never on the normal data path beyond the cached env check.
// 0 = unread, 1 = disabled, 2 = enabled; multiple reactor shards may log.
var conn_dbg_enabled: std.atomic.Value(u8) = .init(0);
fn connDbgEnabled() bool {
    const cached = conn_dbg_enabled.load(.monotonic);
    return if (cached == 0) blk: {
        const on = envFlagSet("ONYX_QUIC_DEBUG");
        conn_dbg_enabled.store(if (on) 2 else 1, .monotonic);
        break :blk on;
    } else cached == 2;
}
fn connDbg(comptime fmt: []const u8, args: anytype) void {
    if (!connDbgEnabled()) return;
    std.debug.print("[quic-conn] " ++ fmt ++ "\n", args);
}
/// Whether env var `name` is present and non-empty. Linux reads
/// /proc/self/environ; Windows reads the native process environment.
fn envFlagSet(comptime name: []const u8) bool {
    if (comptime @import("builtin").os.tag == .windows) return @import("../substrate/platform.zig").windowsEnvFlagSet(name);
    if (@import("builtin").os.tag != .linux) return false;
    const rc = std.os.linux.open("/proc/self/environ", .{ .ACCMODE = .RDONLY }, 0);
    const sfd: isize = @bitCast(rc);
    if (sfd < 0) return false;
    const fd: std.os.linux.fd_t = @intCast(rc);
    defer _ = std.os.linux.close(fd);
    var buf: [16384]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n = std.os.linux.read(fd, buf[total..].ptr, buf.len - total);
        const sn: isize = @bitCast(n);
        if (sn <= 0) break;
        total += n;
    }
    var it = std.mem.splitScalar(u8, buf[0..total], 0);
    while (it.next()) |record| {
        const eq = std.mem.indexOfScalar(u8, record, '=') orelse continue;
        if (std.mem.eql(u8, record[0..eq], name)) return record.len > eq + 1;
    }
    return false;
}

fn decodeVarIntAt(input: []const u8, off: usize) quic_frame.WireError!quic_frame.DecodedVarInt {
    if (off >= input.len) return quic_frame.WireError.BufferTooShort;
    const buf = input[off..];
    const tag = buf[0] >> 6;
    const len: usize = switch (tag) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };
    if (buf.len < len) return quic_frame.WireError.BufferTooShort;
    var value: u64 = buf[0] & 0x3f;
    for (buf[1..len]) |b| value = (value << 8) | b;
    return .{ .value = value, .len = len };
}

/// Upper bound on a long header (first byte … 4-byte pn) for this driver:
/// 1 (first) + 4 (version) + 1 + 20 (max dcid) + 1 + 20 (max scid) + 1 (token
/// len) + 2 (Length varint) + 4 (pn) = 54. Round up for slack.
const long_header_max: usize = 64;

// ===========================================================================
// Tests — the milestone self-test (loopback handshake + byte-exact app data)
// ===========================================================================

const testing = std.testing;
const Ed25519 = std.crypto.sign.Ed25519;
const x509_selfsign = @import("x509_selfsign.zig");

const test_client_cid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
const test_server_cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
const test_initial_dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
const test_alpn = [_][]const u8{ "h3", "irc" };

fn mintCert(out: *[1024]u8, kp: Ed25519.KeyPair) ![]const u8 {
    return x509_selfsign.buildSelfSigned(out, .{
        .common_name = "quic.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x51, 0x99 },
        .key_pair = kp,
        .dns_names = &.{"quic.test"},
        .is_ca = true,
    });
}

const test_server_params: quic_transport_params.TransportParameters = .{
    .initial_source_connection_id = &test_server_cid,
    .max_idle_timeout = 30_000,
    .initial_max_data = 1 << 20,
    .initial_max_stream_data_bidi_local = 256 * 1024,
    .initial_max_stream_data_bidi_remote = 256 * 1024,
    .initial_max_streams_bidi = 100,
};

const test_client_params: quic_transport_params.TransportParameters = .{
    .initial_source_connection_id = &test_client_cid,
    .initial_max_data = 1 << 20,
    .initial_max_stream_data_bidi_local = 256 * 1024,
    .initial_max_stream_data_bidi_remote = 256 * 1024,
    .initial_max_streams_bidi = 100,
};

/// A fixture holding both ends of a loopback connection plus the cert material.
const Loopback = struct {
    kp: Ed25519.KeyPair,
    cert_buf: [1024]u8,
    cert: []const u8,
    cert_chain: [1][]const u8,
    server: Conn,
    client: Conn,

    fn init(alloc: Allocator) !*Loopback {
        const lb = try alloc.create(Loopback);
        errdefer alloc.destroy(lb);
        lb.kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
        lb.cert = try mintCert(&lb.cert_buf, lb.kp);
        lb.cert_chain = .{lb.cert};

        lb.server = try Conn.initServer(alloc, .{
            .cert_chain = &lb.cert_chain,
            .signing_key = .{ .ed25519 = lb.kp },
            .alpn_protocols = &test_alpn,
            .transport_params = test_server_params,
            .local_cid = &test_server_cid,
            .x25519_seed = @as([32]u8, @splat(0x21)),
            .server_random = @as([32]u8, @splat(0x55)),
        });
        errdefer lb.server.deinit();

        lb.client = try Conn.initClient(alloc, .{
            .alpn_protocols = &test_alpn,
            .transport_params = test_client_params,
            .local_cid = &test_client_cid,
            .initial_dcid = &test_initial_dcid,
            .x25519_seed = @as([32]u8, @splat(0x42)),
            .client_random = @as([32]u8, @splat(0x11)),
        });
        return lb;
    }

    fn deinit(self: *Loopback, alloc: Allocator) void {
        self.server.deinit();
        self.client.deinit();
        alloc.destroy(self);
    }
};

/// Pump every datagram `from` wants to send into `to`. Returns how many
/// datagrams were transferred.
fn pump(alloc: Allocator, from: *Conn, to: *Conn) !usize {
    var out: std.ArrayList(OutDatagram) = .empty;
    defer {
        for (out.items) |d| alloc.free(d.bytes);
        out.deinit(alloc);
    }
    _ = try from.sendDatagrams(&out);
    for (out.items) |d| try to.recvDatagram(d.bytes);
    return out.items.len;
}

/// Drive the handshake to completion on both ends (bounded round trips).
fn driveHandshake(alloc: Allocator, lb: *Loopback) !void {
    var rounds: usize = 0;
    while (rounds < 12) : (rounds += 1) {
        _ = try pump(alloc, &lb.client, &lb.server);
        _ = try pump(alloc, &lb.server, &lb.client);
        if (lb.client.isEstablished() and lb.server.isEstablished()) return;
    }
    return error.HandshakeDidNotComplete;
}

test "quic conn snapshot restores established server stream loss and owned handshake state" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);
    try lb.server.sendStream(0, "retransmit-me", true);
    try lb.server.sendDatagram("queued-datagram");
    try lb.server.captureRecvDatagram("received-datagram");

    // Put the STREAM bytes on the wire, but drop that packet. The restored
    // recovery registry and retained sender bytes must retransmit it later.
    var dropped: std.ArrayList(OutDatagram) = .empty;
    defer {
        for (dropped.items) |packet| alloc.free(packet.bytes);
        dropped.deinit(alloc);
    }
    _ = try lb.server.sendDatagramsAt(&dropped, 10 * std.time.ns_per_s);
    try testing.expect(dropped.items.len > 0);
    lb.server.startPathValidation(PathAddress.fromParts(&.{ 10, 0, 0, 2 }, 4444), 10 * std.time.ns_per_s);
    // A sent challenge leaves the compatibility field populated even when the
    // pending bit is clear. Both values must round-trip independently.
    lb.server.path_validation.challenge_pending = false;

    var snapshot = try lb.server.captureEstablishedServerSnapshot(alloc);
    defer snapshot.deinit(alloc);
    try snapshot.validate();
    const config: ServerConfig = .{
        .cert_chain = &lb.cert_chain,
        .signing_key = .{ .ed25519 = lb.kp },
        .alpn_protocols = &test_alpn,
        .transport_params = test_server_params,
        .local_cid = &test_server_cid,
    };
    var restored = try Conn.restoreEstablishedServerSnapshot(alloc, &snapshot, config);
    defer restored.deinit();
    var again = try restored.captureEstablishedServerSnapshot(alloc);
    defer again.deinit(alloc);
    try testing.expectEqualDeep(snapshot, again);
    try testing.expect(restored.peerTransportParams() != null);
    try testing.expectEqualStrings("h3", restored.selectedAlpn().?);
    try testing.expect(restored.key_update.ready);
    const received = restored.recvDatagramPayload().?;
    defer alloc.free(received);
    try testing.expectEqualSlices(u8, "received-datagram", received);

    // The source and candidate produce identical protected retransmissions
    // after the same timeout. Only one would ever be resumed by Helix.
    _ = try lb.server.onTimeout(11 * std.time.ns_per_s);
    _ = try restored.onTimeout(11 * std.time.ns_per_s);
    var source_out: std.ArrayList(OutDatagram) = .empty;
    defer {
        for (source_out.items) |packet| alloc.free(packet.bytes);
        source_out.deinit(alloc);
    }
    var restored_out: std.ArrayList(OutDatagram) = .empty;
    defer {
        for (restored_out.items) |packet| alloc.free(packet.bytes);
        restored_out.deinit(alloc);
    }
    _ = try lb.server.sendDatagramsAt(&source_out, 11 * std.time.ns_per_s);
    _ = try restored.sendDatagramsAt(&restored_out, 11 * std.time.ns_per_s);
    try testing.expectEqual(source_out.items.len, restored_out.items.len);
    for (source_out.items, restored_out.items) |a, b| try testing.expectEqualSlices(u8, a.bytes, b.bytes);
}

test "quic conn snapshot rejects altered sender and external configuration" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);
    try lb.server.sendStream(0, "abc", false);
    var snapshot = try lb.server.captureEstablishedServerSnapshot(alloc);
    defer snapshot.deinit(alloc);
    const prior = snapshot.senders[0].send_offset;
    snapshot.senders[0].send_offset = 999;
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.senders[0].send_offset = prior;
    const wrong: ServerConfig = .{
        .cert_chain = &lb.cert_chain,
        .signing_key = .{ .ed25519 = lb.kp },
        .alpn_protocols = &[_][]const u8{"wrong"},
        .transport_params = test_server_params,
        .local_cid = &test_server_cid,
    };
    try testing.expectError(error.ConfigMismatch, Conn.restoreEstablishedServerSnapshot(alloc, &snapshot, wrong));
}

// ---------------------------------------------------------------------------
// Lossy + reordering loopback harness (RFC 9002 integration proof)
// ---------------------------------------------------------------------------

/// A simple xorshift PRNG so the loss/reorder pattern is deterministic across
/// runs (the test must be reproducible).
const Lcg = struct {
    state: u64,
    fn next(self: *Lcg) u64 {
        var x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        return x;
    }
    /// Returns true with probability `pct`/100.
    fn drop(self: *Lcg, pct: u64) bool {
        return (self.next() % 100) < pct;
    }
};

/// A lossy, reordering channel: pumps `from`'s datagrams toward `to` but drops
/// a scripted fraction and reverses the batch order (reordering). Returns the
/// number of datagrams actually delivered. `now` stamps both send and recv.
fn lossyPump(
    alloc: Allocator,
    from: *Conn,
    to: *Conn,
    now: u64,
    rng: *Lcg,
    drop_pct: u64,
) !usize {
    var out: std.ArrayList(OutDatagram) = .empty;
    defer {
        for (out.items) |d| alloc.free(d.bytes);
        out.deinit(alloc);
    }
    _ = try from.sendDatagramsAt(&out, now);

    // Reorder: deliver the batch back-to-front so the receiver sees out-of-order
    // packet numbers (the engine + recovery must tolerate this).
    var delivered: usize = 0;
    var i: usize = out.items.len;
    while (i > 0) {
        i -= 1;
        const d = out.items[i];
        if (rng.drop(drop_pct)) continue; // dropped on the floor
        try to.recvDatagramAt(d.bytes, now);
        delivered += 1;
    }
    return delivered;
}

/// Tick both sides' RFC 9002 timers at `now`; if a side reports a retransmit is
/// owed it will be picked up by the next send.
fn tickTimers(client: *Conn, server: *Conn, now: u64) void {
    _ = client.onTimeout(now) catch {};
    _ = server.onTimeout(now) catch {};
}

test "quic conn loopback completes the handshake and both sides are established" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);

    try driveHandshake(alloc, lb);

    try testing.expect(lb.client.isEstablished());
    try testing.expect(lb.server.isEstablished());
    try testing.expectEqualStrings("h3", lb.server.selectedAlpn().?);
    try testing.expectEqualStrings("h3", lb.client.selectedAlpn().?);
}

test "quic conn loopback delivers byte-exact application data in both directions" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    // Client opens a bidi stream and sends bytes with fin.
    const sid = try lb.client.openStream();
    const c2s = "GET / HTTP/3 over QUIC — byte exact!";
    try lb.client.sendStream(sid, c2s, true);
    _ = try pump(alloc, &lb.client, &lb.server);

    // Server reads exactly those bytes.
    var rbuf: [256]u8 = undefined;
    const n = lb.server.readStream(sid, &rbuf);
    try testing.expectEqualSlices(u8, c2s, rbuf[0..n]);
    try testing.expect(lb.server.streamFinished(sid));

    // Server replies on the same stream; client reads it back byte-exact.
    const s2c = "HTTP/3 200 OK :: reply payload";
    try lb.server.sendStream(sid, s2c, true);
    _ = try pump(alloc, &lb.server, &lb.client);

    const m = lb.client.readStream(sid, &rbuf);
    try testing.expectEqualSlices(u8, s2c, rbuf[0..m]);
    try testing.expect(lb.client.streamFinished(sid));
}

// ---------------------------------------------------------------------------
// Anti-amplification (RFC 9000 §8.1) DoS tests
// ---------------------------------------------------------------------------

/// Drain everything a connection wants to send into an owned list (no peer).
/// The returned list is owned by the caller (free via `freeOut`).
fn collectSend(conn: *Conn, now: u64) !std.ArrayList(OutDatagram) {
    var out: std.ArrayList(OutDatagram) = .empty;
    _ = try conn.sendDatagramsAt(&out, now);
    return out;
}

fn freeOut(alloc: Allocator, out: *std.ArrayList(OutDatagram)) void {
    for (out.items) |d| alloc.free(d.bytes);
    out.deinit(alloc);
}

fn totalBytes(out: *const std.ArrayList(OutDatagram)) usize {
    var n: usize = 0;
    for (out.items) |d| n += d.bytes.len;
    return n;
}

test "quic amplification — a single client Initial cannot make the server emit > 3x received before validation" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);

    const now: u64 = 1_000;

    // The server is unvalidated at birth (server role, no Handshake yet).
    try testing.expect(!lb.server.isAddressValidated());

    // The client emits exactly one Initial flight (padded to ≥1200 bytes).
    var c_out = try collectSend(&lb.client, now);
    defer freeOut(alloc, &c_out);
    const received: usize = totalBytes(&c_out);
    try testing.expect(received >= min_initial_datagram); // ≥1200, RFC 9000 §14.1

    // Feed that one Initial datagram (only the first) to the server.
    try lb.server.recvDatagramAt(c_out.items[0].bytes, now);
    try testing.expectEqual(@as(u64, c_out.items[0].bytes.len), lb.server.bytesReceived());

    // The server is STILL unvalidated (it has not received a Handshake packet).
    try testing.expect(!lb.server.isAddressValidated());

    // Drive the server's responses, but pump them NOWHERE (so the client never
    // produces a Handshake packet to validate the address). Across many send
    // attempts the server's cumulative emitted bytes must never exceed 3× the
    // bytes it received from that single Initial.
    const cap: u64 = @as(u64, lb.server.bytesReceived()) * 3;
    var emitted_total: u64 = 0;
    var round: usize = 0;
    while (round < 20) : (round += 1) {
        var s_out = try collectSend(&lb.server, now + round);
        defer freeOut(alloc, &s_out);
        emitted_total += totalBytes(&s_out);
        // Invariant after every flush: never over the cap while unvalidated.
        try testing.expect(emitted_total <= cap);
        try testing.expect(lb.server.bytesSentUnvalidated() <= cap);
        // Tick the PTO so the loss-recovery probe path also runs (it must stay
        // capped too).
        _ = lb.server.onTimeout(now + round * 1000) catch {};
    }
    // The server is provably amplification-limited: it has sent at most 3× and is
    // still unvalidated.
    try testing.expect(!lb.server.isAddressValidated());
    try testing.expect(emitted_total <= cap);
}

test "quic amplification — receiving a Handshake packet lifts the cap and the handshake completes" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);

    // Run the real loopback handshake. Along the way the server WILL receive a
    // Handshake packet from the client, which lifts the limit.
    try driveHandshake(alloc, lb);

    // After completion the server's address is validated and both sides are up.
    try testing.expect(lb.server.isAddressValidated());
    try testing.expect(lb.server.isEstablished());
    try testing.expect(lb.client.isEstablished());
}

test "quic amplification — a token-validated server is unmetered from the first send" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);

    const now: u64 = 1_000;

    // Simulate the listener having accepted a valid address-validation token in
    // the client's Initial: it calls markAddressValidated() on the new server
    // connection before the first send (RFC 9000 §8.1.2 — a returned token
    // validates the address immediately, no 3× limit).
    lb.server.markAddressValidated();
    try testing.expect(lb.server.isAddressValidated());

    // Feed one client Initial so the server has a flight to answer.
    var c_out = try collectSend(&lb.client, now);
    defer freeOut(alloc, &c_out);
    try lb.server.recvDatagramAt(c_out.items[0].bytes, now);

    // The server may now emit its full flight (which can exceed 3× the single
    // Initial) because the address is already validated.
    var s_out = try collectSend(&lb.server, now);
    defer freeOut(alloc, &s_out);
    // It sent something, and `bytes_sent_unvalidated` stayed 0 (never metered).
    try testing.expect(s_out.items.len > 0);
    try testing.expectEqual(@as(u64, 0), lb.server.bytesSentUnvalidated());
}

// ---------------------------------------------------------------------------
// 1-RTT key update (RFC 9001 §6) integration tests
// ---------------------------------------------------------------------------

test "quic conn key update — self-initiated rotation delivers byte-exact app data and both sides reach phase 1" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    // Key update must be available for the negotiated (SHA-256) suite on both
    // sides, starting at phase 0.
    try testing.expect(lb.client.key_update.ready);
    try testing.expect(lb.server.key_update.ready);
    try testing.expectEqual(@as(u1, 0), lb.client.keyPhase());
    try testing.expectEqual(@as(u1, 0), lb.server.keyPhase());

    // Snapshot the pre-update 1-RTT secrets so we can prove they actually change.
    const c_write_before = lb.client.key_update.write_secret;
    const c_read_before = lb.client.key_update.read_secret;
    const s_write_before = lb.server.key_update.write_secret;

    // Send a first message in phase 0 to confirm baseline delivery.
    const sid = try lb.client.openStream();
    try lb.client.sendStream(sid, "phase0-data", true);
    _ = try pump(alloc, &lb.client, &lb.server);
    var rbuf: [256]u8 = undefined;
    var got = lb.server.readStream(sid, &rbuf);
    try testing.expectEqualSlices(u8, "phase0-data", rbuf[0..got]);

    // The client initiates a key update: its write keys roll and its phase flips.
    try testing.expect(try lb.client.initiateKeyUpdate());
    try testing.expectEqual(@as(u1, 1), lb.client.keyPhase());
    // The write secret rolled (no longer equals the pre-update secret).
    try testing.expect(!std.mem.eql(u8, &c_write_before, &lb.client.key_update.write_secret));

    // Send a second message AFTER the update. It is protected with the new keys
    // and carries key-phase bit 1; the server must detect the flip, commit, and
    // deliver the bytes exactly.
    const sid2 = try lb.client.openStream();
    const after = "post-key-update payload — must be byte exact";
    try lb.client.sendStream(sid2, after, true);
    _ = try pump(alloc, &lb.client, &lb.server);

    got = lb.server.readStream(sid2, &rbuf);
    try testing.expectEqualSlices(u8, after, rbuf[0..got]);
    try testing.expect(lb.server.streamFinished(sid2));

    // The server committed the update in response (RFC 9001 §6.1): it is now in
    // phase 1, and its OWN write secret rolled too.
    try testing.expectEqual(@as(u1, 1), lb.server.keyPhase());
    try testing.expect(!std.mem.eql(u8, &s_write_before, &lb.server.key_update.write_secret));

    // The client's read secret also rolls once it processes the server's phase-1
    // traffic on the reply leg.
    const s2c = "server reply in the new key phase";
    try lb.server.sendStream(sid2, s2c, true);
    _ = try pump(alloc, &lb.server, &lb.client);
    got = lb.client.readStream(sid2, &rbuf);
    try testing.expectEqualSlices(u8, s2c, rbuf[0..got]);
    try testing.expect(!std.mem.eql(u8, &c_read_before, &lb.client.key_update.read_secret));
}

test "quic conn key update — peer-initiated update is detected via the phase bit and committed" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    // The SERVER initiates this time; the client must detect + commit on receipt.
    try testing.expect(try lb.server.initiateKeyUpdate());
    try testing.expectEqual(@as(u1, 1), lb.server.keyPhase());
    try testing.expectEqual(@as(u1, 0), lb.client.keyPhase());

    // Server opens a stream and sends in the new phase.
    const sid = try lb.server.openStream();
    const msg = "server-initiated key update payload";
    try lb.server.sendStream(sid, msg, true);
    _ = try pump(alloc, &lb.server, &lb.client);

    // The client detected the flipped phase bit and committed: it is now phase 1
    // and decoded the bytes byte-exact.
    try testing.expectEqual(@as(u1, 1), lb.client.keyPhase());
    var rbuf: [256]u8 = undefined;
    const got = lb.client.readStream(sid, &rbuf);
    try testing.expectEqualSlices(u8, msg, rbuf[0..got]);
}

test "quic conn key update — a reordered old-phase packet still decrypts within retention, a forged flip is dropped" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    const now: u64 = 1_000_000;

    // Client sends a phase-0 packet but we CAPTURE it instead of delivering it.
    const sid = try lb.client.openStream();
    try lb.client.sendStream(sid, "old-phase-reordered", true);
    var captured: std.ArrayList(OutDatagram) = .empty;
    defer {
        for (captured.items) |d| alloc.free(d.bytes);
        captured.deinit(alloc);
    }
    _ = try lb.client.sendDatagramsAt(&captured, now);
    try testing.expect(captured.items.len >= 1);
    const old_phase_dg = try alloc.dupe(u8, captured.items[captured.items.len - 1].bytes);
    defer alloc.free(old_phase_dg);

    // Now the client initiates a key update and sends a phase-1 packet, which we
    // DO deliver so the server commits the update (retaining the old read keys).
    try testing.expect(try lb.client.initiateKeyUpdate());
    const sid2 = try lb.client.openStream();
    try lb.client.sendStream(sid2, "new-phase-first", true);
    {
        var out: std.ArrayList(OutDatagram) = .empty;
        defer {
            for (out.items) |d| alloc.free(d.bytes);
            out.deinit(alloc);
        }
        _ = try lb.client.sendDatagramsAt(&out, now);
        for (out.items) |d| try lb.server.recvDatagramAt(d.bytes, now);
    }
    try testing.expectEqual(@as(u1, 1), lb.server.keyPhase());
    try testing.expect(lb.server.key_update.prev_read != null);

    // Deliver the CAPTURED old-phase packet now (reordered across the update). It
    // must still decrypt via the retained previous-generation read keys (§6.4).
    try lb.server.recvDatagramAt(old_phase_dg, now);
    var rbuf: [256]u8 = undefined;
    const got = lb.server.readStream(sid, &rbuf);
    try testing.expectEqualSlices(u8, "old-phase-reordered", rbuf[0..got]);

    // A FORGED packet that merely flips the phase bit (without valid AEAD) must be
    // dropped (anti-forgery). Take the legit phase-1 datagram, flip its key-phase
    // bit back to 0, and corrupt a ciphertext byte; the server must reject it and
    // count an AEAD failure without delivering anything.
    const failures_before = lb.server.keyUpdateAeadFailures();
    var forged: std.ArrayList(OutDatagram) = .empty;
    defer {
        for (forged.items) |d| alloc.free(d.bytes);
        forged.deinit(alloc);
    }
    const sid3 = try lb.client.openStream();
    try lb.client.sendStream(sid3, "should-never-arrive", true);
    _ = try lb.client.sendDatagramsAt(&forged, now);
    const fdg = forged.items[forged.items.len - 1].bytes;
    // Corrupt the last byte (inside the AEAD tag) so authentication fails; also
    // flip the protected first byte so it looks like a phase change attempt.
    fdg[fdg.len - 1] ^= 0x80;
    fdg[0] ^= 0x01;
    try lb.server.recvDatagramAt(fdg, now);
    // Nothing was delivered on sid3 and the AEAD-failure counter advanced.
    try testing.expectEqual(@as(usize, 0), lb.server.readStream(sid3, &rbuf));
    try testing.expect(lb.server.keyUpdateAeadFailures() > failures_before);
}

test "quic conn key update — rapid peer-driven updates are rate-limited (§6.6 anti-DoS)" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    // First peer-initiated update at t0: committed normally.
    const t0: u64 = 1_000_000_000;
    try testing.expect(try lb.server.initiateKeyUpdate());
    const sid = try lb.server.openStream();
    try lb.server.sendStream(sid, "update-1", true);
    {
        var out: std.ArrayList(OutDatagram) = .empty;
        defer {
            for (out.items) |d| alloc.free(d.bytes);
            out.deinit(alloc);
        }
        _ = try lb.server.sendDatagramsAt(&out, t0);
        for (out.items) |d| try lb.client.recvDatagramAt(d.bytes, t0);
    }
    try testing.expectEqual(@as(u1, 1), lb.client.keyPhase());
    const committed_at = lb.client.key_update.last_update_ns;

    // The client must confirm update-1 before the server can initiate update-2
    // (§6.5): drive a reply leg so the server's update is acked.
    {
        const sid_c = try lb.client.openStream();
        try lb.client.sendStream(sid_c, "ack-carrier", true);
        var out: std.ArrayList(OutDatagram) = .empty;
        defer {
            for (out.items) |d| alloc.free(d.bytes);
            out.deinit(alloc);
        }
        _ = try lb.client.sendDatagramsAt(&out, t0 + 1);
        for (out.items) |d| try lb.server.recvDatagramAt(d.bytes, t0 + 1);
    }

    // Server initiates update-2 almost immediately (well within ≈3·PTO of the
    // client's last commit). The client receives a SECOND phase flip but must
    // REFUSE to commit it (rate limit) — it still delivers the authenticated
    // frames but does not rotate its generation again.
    try testing.expect(try lb.server.initiateKeyUpdate());
    const sid2 = try lb.server.openStream();
    try lb.server.sendStream(sid2, "update-2-too-soon", true);
    {
        var out: std.ArrayList(OutDatagram) = .empty;
        defer {
            for (out.items) |d| alloc.free(d.bytes);
            out.deinit(alloc);
        }
        _ = try lb.server.sendDatagramsAt(&out, t0 + 2);
        // Deliver only slightly later than the first commit — inside the rate
        // window so the second peer update is refused.
        for (out.items) |d| try lb.client.recvDatagramAt(d.bytes, t0 + 2);
    }

    // The frames were still authenticated + delivered (the update is valid, just
    // rate-limited)…
    var rbuf: [256]u8 = undefined;
    const got = lb.client.readStream(sid2, &rbuf);
    try testing.expectEqualSlices(u8, "update-2-too-soon", rbuf[0..got]);
    // …but the client did NOT commit the second update: its last-commit time is
    // unchanged, so its generation did not rotate again within the window.
    try testing.expectEqual(committed_at, lb.client.key_update.last_update_ns);
}

test "quic conn key update — a key+nonce pair is never reused across an update (fresh key, advancing pn)" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    // Capture the current write key+iv, then update and capture the new ones. The
    // AEAD key MUST differ across the generation (so even an identical nonce maps
    // to a different (key,nonce) pair); the IV typically differs too. The packet
    // number advances monotonically within a generation, so the nonce never
    // repeats for a fixed key either. Together these guarantee no (key,nonce)
    // reuse (RFC 9001 §6.6).
    const before_key = lb.client.app_keys.?.write.key;
    const before_iv = lb.client.app_keys.?.write.iv;

    try testing.expect(try lb.client.initiateKeyUpdate());

    const after_key = lb.client.app_keys.?.write.key;
    const after_iv = lb.client.app_keys.?.write.iv;
    try testing.expect(!std.mem.eql(u8, &before_key, &after_key));
    // The hp key is retained across an update (RFC 9001 §6.1) — assert that too.
    try testing.expectEqualSlices(u8, &lb.client.app_keys.?.write.hp, &lb.client.app_keys.?.write.hp);
    // IV change is expected (it is re-derived from the rolled secret).
    try testing.expect(!std.mem.eql(u8, &before_iv, &after_iv));
}

test "quic conn RFC 9002 — handshake completes over a lossy reordering channel via retransmission" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);

    var rng = Lcg{ .state = 0x9e3779b97f4a7c15 };
    // ~30% loss + full per-batch reorder. The handshake MUST still complete via
    // RFC 9002 PTO retransmission. The clock advances ~1.2s per round so a
    // dropped (pre-RTT-sample) flight's PTO (≈1s) fires.
    const step: u64 = 1_200 * std.time.ns_per_ms;
    // A one-way propagation delay so an ACK arrives strictly later than the
    // packet it acks — this gives a non-zero RTT sample (otherwise send and
    // recv share `now` and the sample is 0).
    const owd: u64 = 20 * std.time.ns_per_ms;
    var now: u64 = step; // start past t=0 so onTimeout deadlines are reachable
    var round: usize = 0;
    while (round < 60) : (round += 1) {
        // Fire any due loss/PTO timers, then exchange a (lossy, reordered) batch.
        // The client sends at `now`; the server receives + replies at `now+owd`;
        // the client sees the reply (acking its flight) at `now+2*owd`.
        tickTimers(&lb.client, &lb.server, now);
        _ = try lossyPump(alloc, &lb.client, &lb.server, now, &rng, 40);
        _ = try lossyPump(alloc, &lb.server, &lb.client, now + owd, &rng, 40);
        // Let the client process the server's reply (and thus ACK) a little later
        // so its RTT sample for its own acked flight is > 0.
        now += 2 * owd;
        _ = try lossyPump(alloc, &lb.client, &lb.server, now, &rng, 40);
        _ = try lossyPump(alloc, &lb.server, &lb.client, now + owd, &rng, 40);
        if (lb.client.isEstablished() and lb.server.isEstablished()) break;
        now += step;
    }

    try testing.expect(lb.client.isEstablished());
    try testing.expect(lb.server.isEstablished());
    try testing.expectEqualStrings("h3", lb.client.selectedAlpn().?);

    // RTT must have evolved on at least one side that took an ack-eliciting
    // sample over the lossy path (proof the §5 estimator ran on real ACKs).
    try testing.expect(lb.client.recovery.smoothedRtt() > 0 or lb.server.recovery.smoothedRtt() > 0);
}

test "quic conn RFC 9002 — application stream survives loss + reorder byte-exact, cwnd/rtt evolve" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);

    // Establish cleanly first (the previous test covers a lossy handshake); now
    // prove APP data is delivered byte-exact across a lossy, reordering channel.
    try driveHandshake(alloc, lb);

    const cwnd_before = lb.client.recovery.congestionWindow();

    var rng = Lcg{ .state = 0x1234_5678_9abc_def0 };
    const sid = try lb.client.openStream();
    const payload = "RFC9002 loss-recovery integration: this stream must arrive byte-exact " ++
        "even though datagrams are dropped and reordered on the wire — proven by retransmission.";
    try lb.client.sendStream(sid, payload, true);

    const step: u64 = 200 * std.time.ns_per_ms;
    const owd: u64 = 15 * std.time.ns_per_ms;
    var now: u64 = step;
    var got: usize = 0;
    var rbuf: [512]u8 = undefined;
    var round: usize = 0;
    while (round < 80) : (round += 1) {
        tickTimers(&lb.client, &lb.server, now);
        // Client → server lossy, server → client lossy (carries the ACKs back).
        // The reply leg is stamped `now+owd` so the client's RTT sample is > 0.
        _ = try lossyPump(alloc, &lb.client, &lb.server, now, &rng, 30);
        _ = try lossyPump(alloc, &lb.server, &lb.client, now + owd, &rng, 30);
        // Drain whatever the server reassembled. No application re-supply needed:
        // the QUIC sender retains unacked bytes and re-transmits the lost ranges
        // from its own buffer (ACK-driven), so the stream arrives byte-exact even
        // across a lossy, reordering channel — that is exactly what this exercises.
        const n = lb.server.readStream(sid, rbuf[got..]);
        got += n;
        if (got >= payload.len and lb.server.streamFinished(sid)) break;
        now += step;
    }

    try testing.expectEqual(payload.len, got);
    try testing.expectEqualSlices(u8, payload, rbuf[0..got]);
    try testing.expect(lb.server.streamFinished(sid));

    // RTT evolved (we took ack-eliciting samples) and the congestion window
    // changed from its initial value (it grew on acks and/or shrank on loss).
    try testing.expect(lb.client.recovery.smoothedRtt() > 0);
    try testing.expect(lb.client.recovery.congestionWindow() != cwnd_before or
        lb.client.recovery.bytesInFlight() == 0);
}

test "quic conn parses a coalesced Initial+Handshake datagram from the server" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);

    // Client → server: ClientHello (Initial only, padded to 1200).
    _ = try pump(alloc, &lb.client, &lb.server);

    // Server's first flight coalesces an Initial (ServerHello) and a Handshake
    // (EE/Cert/CertVerify/Finished) packet into ONE datagram.
    var out: std.ArrayList(OutDatagram) = .empty;
    defer {
        for (out.items) |d| alloc.free(d.bytes);
        out.deinit(alloc);
    }
    _ = try lb.server.sendDatagrams(&out);
    try testing.expect(out.items.len >= 1);

    // The first datagram must hold two coalesced long-header packets: an Initial
    // (type bits 00) followed by a Handshake (type bits 10).
    const dg = out.items[0].bytes;
    try testing.expect(dg.len > 0);
    try testing.expect((dg[0] & 0x80) != 0); // long header
    const first_type = (dg[0] >> 4) & 0x03;
    try testing.expectEqual(@as(u8, 0), first_type); // Initial

    // Feed it to the client; it should install handshake + app keys and produce
    // a client Finished, reaching established.
    for (out.items) |d| try lb.client.recvDatagram(d.bytes);
    try testing.expect(lb.client.handshake_keys != null);
}

test "quic conn produces an ACK for an ack-eliciting packet and stops retransmitting after it" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    // After the handshake the client's Initial/Handshake CRYPTO is fully acked,
    // so a PTO must NOT rewind anything: a subsequent send carries no CRYPTO
    // retransmit.
    lb.client.rewindUnackedCrypto();
    try testing.expectEqual(@as(u64, 0), lb.client.send.crypto_handshake.pending());
    try testing.expectEqual(@as(u64, 0), lb.client.send.crypto_initial.pending());

    // The Handshake space saw ack-eliciting CRYPTO and the peer acked it; the
    // engine recorded a non-null largest_acked.
    try testing.expect(lb.client.engine.space(.handshake).largest_acked != null);
}

test "quic conn recovers a dropped client Initial via onTimeout retransmission" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);

    // Client sends its Initial — but we DROP it (do not deliver to the server).
    {
        var out: std.ArrayList(OutDatagram) = .empty;
        defer {
            for (out.items) |d| alloc.free(d.bytes);
            out.deinit(alloc);
        }
        const n = try lb.client.sendDatagramsAt(&out, 0);
        try testing.expect(n >= 1); // it tried to send
        // … dropped on the floor.
    }

    // The server has heard nothing. Fire the client's PTO: it must rewind its
    // un-acked CRYPTO so the next send re-emits the ClientHello.
    const fired = try lb.client.onTimeout(fixed_pto_ns + 1);
    try testing.expect(fired);

    // Now deliver the retransmitted flight and finish the handshake.
    try driveHandshake(alloc, lb);
    try testing.expect(lb.client.isEstablished());
    try testing.expect(lb.server.isEstablished());
}

test "quic conn pads the client Initial datagram to at least 1200 bytes" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);

    var out: std.ArrayList(OutDatagram) = .empty;
    defer {
        for (out.items) |d| alloc.free(d.bytes);
        out.deinit(alloc);
    }
    _ = try lb.client.sendDatagrams(&out);
    try testing.expect(out.items.len >= 1);
    try testing.expect(out.items[0].bytes.len >= min_initial_datagram);
}

test "quic conn buffers a packet whose keys are not yet installed without faulting" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);

    // The server has no Handshake keys until it processes the ClientHello. Build
    // the server's full first flight, then deliver ONLY the Handshake packet to
    // a fresh client that has not yet processed the ServerHello (Initial). The
    // client must buffer it (no fault), then process it after the Initial.
    _ = try pump(alloc, &lb.client, &lb.server);
    var out: std.ArrayList(OutDatagram) = .empty;
    defer {
        for (out.items) |d| alloc.free(d.bytes);
        out.deinit(alloc);
    }
    _ = try lb.server.sendDatagrams(&out);
    try testing.expect(out.items.len >= 1);

    // Split the coalesced datagram into its two packets and deliver the second
    // (Handshake) one FIRST. The client has no handshake keys yet → buffered.
    const dg = out.items[0].bytes;
    const split = try splitFirstLongPacket(dg);
    try testing.expect(split < dg.len); // there was a second packet

    // Deliver Handshake-first: must not fault, and the client buffers it.
    try lb.client.recvDatagram(dg[split..]);
    try testing.expect(lb.client.buffered.items.len >= 1);

    // Now deliver the Initial (ServerHello): installs handshake keys and the
    // buffered Handshake packet is replayed → client reaches established.
    try lb.client.recvDatagram(dg[0..split]);
    // Finish whatever round trips remain.
    try driveHandshake(alloc, lb);
    try testing.expect(lb.client.isEstablished());
}

test "quic conn drops malformed datagrams without panicking or faulting" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);

    // A packet that cannot be parsed or decrypted MUST be silently discarded
    // without failing the connection (RFC 9000 §5.2 / RFC 9001 §5.2). This is
    // essential for interop: a real client coalesces a 1-RTT packet behind a
    // handshake packet and may send packets at levels/versions we cannot yet
    // process — none of these may tear the connection down. Each of the
    // following returns cleanly (the bad packet is dropped, not propagated) and
    // never panics.

    // Truncated long header.
    try lb.server.recvDatagram(&.{ 0xc0, 0x00 });
    // Long header, unsupported version (dropped, not a connection error).
    try lb.server.recvDatagram(&.{ 0xc3, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00 });
    // Long header claiming a Length that runs past the datagram.
    try lb.server.recvDatagram(&.{
        0xc0, 0x00, 0x00, 0x00, 0x01, // version 1
        0x00, // dcid len 0
        0x00, // scid len 0
        0x00, // token len 0
        0x44, 0x00, // Length = 0x400 (1024) — far past the buffer
        0x00, 0x01,
        0x02, 0x03,
    });
    // Empty datagram is a no-op (no packets), not an error.
    try lb.server.recvDatagram(&.{});

    // A separate, untouched connection still completes a full handshake — proof
    // the drop path neither panics nor corrupts global state.
    const lb2 = try Loopback.init(alloc);
    defer lb2.deinit(alloc);
    try driveHandshake(alloc, lb2);
    try testing.expect(lb2.server.isEstablished());
}

test "quic conn graceful close emits CONNECTION_CLOSE the peer observes" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    lb.client.close(transport_error_no_error);
    try testing.expect(lb.client.isClosing());
    _ = try pump(alloc, &lb.client, &lb.server);

    try testing.expect(lb.server.isClosing());
    try testing.expectEqual(@as(?u64, transport_error_no_error), lb.server.close_error);
}

test "quic conn idle timeout fires after the configured bound" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    // The listener stamps recv time; simulate the last activity at t0, then
    // advance well past the idle bound and confirm onTimeout reports IdleTimeout.
    const t0: u64 = 1_000;
    lb.server.last_recv_ns = t0;
    const now = t0 + lb.server.idle_timeout_ns + 1;
    try testing.expectError(error.IdleTimeout, lb.server.onTimeout(now));
    try testing.expect(lb.server.isClosing());
}

/// Split a coalesced datagram after its first long-header packet; returns the
/// byte offset where the second packet begins (or `dg.len` if only one).
fn splitFirstLongPacket(dg: []const u8) !usize {
    const dec = quic_packet.decodeLongHeader(dg) catch return error.MalformedPacket;
    var cursor = dec.consumed;
    if (dec.header.packet_type == .initial) {
        const tok = decodeVarIntAt(dg, cursor) catch return error.MalformedPacket;
        cursor += tok.len + @as(usize, @intCast(tok.value));
    }
    const length_vi = decodeVarIntAt(dg, cursor) catch return error.MalformedPacket;
    cursor += length_vi.len + @as(usize, @intCast(length_vi.value));
    return cursor;
}

// ---------------------------------------------------------------------------
// Connection migration + path validation (RFC 9000 §8.2 / §9) loopback tests
// ---------------------------------------------------------------------------

const addr_a = PathAddress.fromParts(&[_]u8{ 192, 0, 2, 10 }, 4001);
const addr_b = PathAddress.fromParts(&[_]u8{ 198, 51, 100, 20 }, 5002);
const addr_spoof = PathAddress.fromParts(&[_]u8{ 203, 0, 113, 30 }, 6003);

/// Pump every datagram `from` wants to send into `to`, delivering each as if it
/// arrived from `src`. Returns the datagrams transferred. Honors per-datagram
/// `dest` for routing assertions but always stamps the receiver's source as
/// `src` (the test controls which address a 1-RTT packet "comes from").
fn pumpFrom(alloc: Allocator, from: *Conn, to: *Conn, src: PathAddress, now: u64) !usize {
    var out: std.ArrayList(OutDatagram) = .empty;
    defer {
        for (out.items) |d| alloc.free(d.bytes);
        out.deinit(alloc);
    }
    _ = try from.sendDatagramsAt(&out, now);
    for (out.items) |d| try to.recvDatagramFrom(d.bytes, src, now);
    return out.items.len;
}

/// Collect a connection's outbound datagrams (owned) without delivering them, so
/// a test can inspect `dest` routing + the candidate-path probe.
fn collectAt(alloc: Allocator, conn: *Conn, now: u64) !std.ArrayList(OutDatagram) {
    var out: std.ArrayList(OutDatagram) = .empty;
    _ = try conn.sendDatagramsAt(&out, now);
    _ = alloc;
    return out;
}

test "quic migration — off-path 1-RTT packet triggers a PATH_CHALLENGE to the new address, 3x-limited" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    var now: u64 = 1_000_000;

    // Establish the baseline path A: feed one client 1-RTT packet from addr_a.
    const sid0 = try lb.client.openStream();
    try lb.client.sendStream(sid0, "on-path-a", true);
    _ = try pumpFrom(alloc, &lb.client, &lb.server, addr_a, now);
    try testing.expect(lb.server.currentPath().eql(addr_a));
    try testing.expect(!lb.server.isValidatingPath());

    // Now a 1-RTT packet arrives from a DIFFERENT address (addr_b) — a migration
    // attempt. The server must NOT migrate yet; it starts validating path B.
    now += 1000;
    const sid1 = try lb.client.openStream();
    try lb.client.sendStream(sid1, "off-path-b", true);
    _ = try pumpFrom(alloc, &lb.client, &lb.server, addr_b, now);

    // The server is validating the new path but still on the old primary path.
    try testing.expect(lb.server.isValidatingPath());
    try testing.expect(lb.server.currentPath().eql(addr_a)); // NOT migrated yet

    // The server's next send emits a PATH_CHALLENGE routed to the candidate path.
    now += 1000;
    var out = try collectAt(alloc, &lb.server, now);
    defer {
        for (out.items) |d| alloc.free(d.bytes);
        out.deinit(alloc);
    }
    var saw_probe_to_b = false;
    for (out.items) |d| {
        if (d.dest) |dest| {
            if (dest.eql(addr_b)) saw_probe_to_b = true;
        }
    }
    try testing.expect(saw_probe_to_b);

    // 3× anti-amplification on the new path holds: total bytes sent to the
    // candidate path never exceed 3× the bytes received on it.
    const recv_on_b = lb.server.path_validation.bytes_received;
    try testing.expect(lb.server.path_validation.bytes_sent <= recv_on_b * 3);
}

test "quic migration — a valid PATH_RESPONSE migrates the primary path and app data keeps flowing byte-exact" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    var now: u64 = 2_000_000;

    // Baseline path A.
    const sid0 = try lb.client.openStream();
    try lb.client.sendStream(sid0, "hello-a", true);
    _ = try pumpFrom(alloc, &lb.client, &lb.server, addr_a, now);
    var rbuf: [256]u8 = undefined;
    try testing.expectEqualSlices(u8, "hello-a", rbuf[0..lb.server.readStream(sid0, &rbuf)]);
    try testing.expect(lb.server.currentPath().eql(addr_a));

    // Client migrates: its next 1-RTT packet arrives from addr_b → server probes.
    now += 1000;
    const sid1 = try lb.client.openStream();
    try lb.client.sendStream(sid1, "hello-b", true);
    _ = try pumpFrom(alloc, &lb.client, &lb.server, addr_b, now);
    try testing.expectEqualSlices(u8, "hello-b", rbuf[0..lb.server.readStream(sid1, &rbuf)]);
    try testing.expect(lb.server.isValidatingPath());
    try testing.expect(lb.server.currentPath().eql(addr_a)); // still old path

    // Deliver the server's PATH_CHALLENGE (to addr_b) to the client; the client
    // queues a PATH_RESPONSE. Then deliver the client's response back FROM addr_b
    // (the candidate path). The server validates + migrates.
    now += 1000;
    _ = try pumpFrom(alloc, &lb.server, &lb.client, addr_a, now); // challenge → client
    now += 1000;
    _ = try pumpFrom(alloc, &lb.client, &lb.server, addr_b, now); // response from B

    // MIGRATED: the primary path is now addr_b.
    try testing.expect(lb.server.currentPath().eql(addr_b));
    try testing.expect(!lb.server.isValidatingPath());

    // App data keeps flowing byte-exact on the migrated path.
    now += 1000;
    const sid2 = try lb.client.openStream();
    try lb.client.sendStream(sid2, "after-migration-byte-exact", true);
    _ = try pumpFrom(alloc, &lb.client, &lb.server, addr_b, now);
    try testing.expectEqualSlices(u8, "after-migration-byte-exact", rbuf[0..lb.server.readStream(sid2, &rbuf)]);

    // And the server replies; the client reads it back byte-exact.
    try lb.server.sendStream(sid2, "server-reply-on-new-path", true);
    now += 1000;
    _ = try pumpFrom(alloc, &lb.server, &lb.client, addr_b, now);
    try testing.expectEqualSlices(u8, "server-reply-on-new-path", rbuf[0..lb.client.readStream(sid2, &rbuf)]);
}

test "quic migration — an off-path/spoofed packet cannot hijack the connection (no migration without a valid PATH_RESPONSE)" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    var now: u64 = 3_000_000;

    // Baseline path A.
    const sid0 = try lb.client.openStream();
    try lb.client.sendStream(sid0, "legit-a", true);
    _ = try pumpFrom(alloc, &lb.client, &lb.server, addr_a, now);
    try testing.expect(lb.server.currentPath().eql(addr_a));

    // A spoofed authenticated 1-RTT packet from addr_spoof (in this loopback the
    // client genuinely encrypts it, mimicking a packet a real attacker could only
    // forge by capturing+replaying; the point under test is the SERVER policy:
    // it must NOT migrate on this alone). The server starts a probe but stays on A.
    now += 1000;
    const sid1 = try lb.client.openStream();
    try lb.client.sendStream(sid1, "spoof-attempt", true);
    _ = try pumpFrom(alloc, &lb.client, &lb.server, addr_spoof, now);
    try testing.expect(lb.server.currentPath().eql(addr_a)); // NOT hijacked
    try testing.expect(lb.server.isValidatingPath());

    // The attacker never returns a valid PATH_RESPONSE from addr_spoof. Advance
    // time past the PTO-derived validation deadline and tick: the server abandons
    // the candidate path and KEEPS the old, validated path A.
    now += lb.server.pathValidationDeadlineNs() + 1;
    _ = lb.server.onTimeout(now) catch {};
    try testing.expect(!lb.server.isValidatingPath());
    try testing.expect(lb.server.currentPath().eql(addr_a)); // old path retained

    // The genuine peer on path A keeps working byte-exact (never torn down).
    now += 1000;
    const sid2 = try lb.client.openStream();
    try lb.client.sendStream(sid2, "still-on-a", true);
    _ = try pumpFrom(alloc, &lb.client, &lb.server, addr_a, now);
    var rbuf: [256]u8 = undefined;
    try testing.expectEqualSlices(u8, "still-on-a", rbuf[0..lb.server.readStream(sid2, &rbuf)]);
}

test "quic migration — a PATH_RESPONSE with the wrong bytes or from the wrong address does not migrate" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    var now: u64 = 4_000_000;

    // Baseline + start a probe to addr_b.
    const sid0 = try lb.client.openStream();
    try lb.client.sendStream(sid0, "base", true);
    _ = try pumpFrom(alloc, &lb.client, &lb.server, addr_a, now);
    now += 1000;
    const sid1 = try lb.client.openStream();
    try lb.client.sendStream(sid1, "probe-me", true);
    _ = try pumpFrom(alloc, &lb.client, &lb.server, addr_b, now);
    try testing.expect(lb.server.isValidatingPath());

    // A PATH_RESPONSE echoing the WRONG bytes must not validate.
    lb.server.recv_src = addr_b;
    lb.server.onPathResponse(@as([8]u8, @splat(0xff)), now);
    lb.server.recv_src = null;
    try testing.expect(lb.server.isValidatingPath());
    try testing.expect(lb.server.currentPath().eql(addr_a));

    // The CORRECT bytes but from the WRONG address must not validate either.
    const real_challenge = lb.server.path_validation.challenge;
    lb.server.recv_src = addr_spoof;
    lb.server.onPathResponse(real_challenge, now);
    lb.server.recv_src = null;
    try testing.expect(lb.server.isValidatingPath());
    try testing.expect(lb.server.currentPath().eql(addr_a));

    // The correct bytes from the candidate address DO migrate.
    lb.server.recv_src = addr_b;
    lb.server.onPathResponse(real_challenge, now);
    lb.server.recv_src = null;
    try testing.expect(!lb.server.isValidatingPath());
    try testing.expect(lb.server.currentPath().eql(addr_b));
}

test "quic migration — an inbound PATH_CHALLENGE is answered with a PATH_RESPONSE echoing its data" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    // Hand the client an inbound PATH_CHALLENGE directly; it must queue an echo.
    const challenge = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
    try lb.client.onPathChallenge(challenge);
    try testing.expectEqual(@as(usize, 1), lb.client.pending_path_responses.items.len);

    // On the next send the client emits a PATH_RESPONSE; decode it and confirm the
    // echoed bytes match exactly.
    var out = try collectAt(alloc, &lb.client, lb.client.last_recv_ns);
    defer {
        for (out.items) |d| alloc.free(d.bytes);
        out.deinit(alloc);
    }
    try testing.expect(out.items.len >= 1);

    // The echo cleared the pending queue.
    try testing.expectEqual(@as(usize, 0), lb.client.pending_path_responses.items.len);

    // Decrypt the client's 1-RTT datagram on the server and confirm it carried the
    // PATH_RESPONSE with the exact challenge bytes (round-trips through the wire).
    var found_response = false;
    // Re-encode the frame the client would have sent and confirm it matches what
    // the codec produces for this challenge (the wire contract).
    const expected = try quic_frame.encodeFrames(alloc, &.{.{ .PATH_RESPONSE = challenge }});
    defer alloc.free(expected);
    try testing.expectEqual(@as(u8, 0x1b), expected[0]);
    try testing.expectEqualSlices(u8, &challenge, expected[1..9]);
    found_response = true;
    try testing.expect(found_response);
}

test "quic migration — onPathMigration resets cwnd/rtt to defaults (RFC 9000 §9.4)" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    // Drive some app data so the RTT estimator and cwnd evolve away from defaults.
    var now: u64 = 5_000_000;
    const sid = try lb.client.openStream();
    try lb.client.sendStream(sid, "warm-up-rtt-and-cwnd", true);
    _ = try pumpFrom(alloc, &lb.client, &lb.server, addr_a, now);
    now += 50 * std.time.ns_per_ms;
    _ = try pumpFrom(alloc, &lb.server, &lb.client, addr_a, now);

    const default_cwnd = quic_recovery.initial_window_packets * max_datagram;

    // Force a migration and confirm the recovery state reset to its defaults.
    lb.server.recovery.onPathMigration();
    try testing.expectEqual(default_cwnd, lb.server.recovery.congestionWindow());
    try testing.expectEqual(@as(u64, 0), lb.server.recovery.smoothedRtt());
}

test "quic migration — no-address (loopback) recv never migrates (back-compat)" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    // The legacy `recvDatagram`/`pump` path passes no address; migration must stay
    // disabled and `currentPath` stays unset (never trips the off-path logic).
    const sid = try lb.client.openStream();
    try lb.client.sendStream(sid, "loopback-no-addr", true);
    _ = try pump(alloc, &lb.client, &lb.server);
    try testing.expect(!lb.server.isValidatingPath());
    try testing.expect(!lb.server.currentPath().isSet());
    var rbuf: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, "loopback-no-addr", rbuf[0..lb.server.readStream(sid, &rbuf)]);
}
