// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SFU-side SRTP/SRTCP crypto hub for the DTLS-SRTP media leg (RFC 3711 / 5764).
//!
//! Increment 1 terminates DTLS per peer (Onyx Server is always the DTLS *server*) and
//! exposes each peer's exported SRTP keying material read-only. This hub turns
//! that material into a *live* SFU crypto context: it decrypts a DTLS-SRTP peer's
//! inbound media under that peer's own key and re-encrypts the recovered
//! plaintext, per recipient, under each recipient's DISTINCT key — so a
//! selective-forwarding unit can relay between peers that do not share a key.
//!
//! Plaintext RTP/RTCP is the SFU's common currency: group-key/SDES and native
//! legs already forward plaintext on this UDP plane, so the DTLS crypto engages
//! ONLY on DTLS legs. When no address is a DTLS-SRTP peer the forwarding path is
//! byte-identical to the pre-DTLS relay.
//!
//! Nonce discipline (the security core). SRTP's AES-CM keystream is
//! `f(key, ssrc, index)`; encrypting two DIFFERENT plaintexts under the same
//! (key, ssrc, index) is a two-time-pad that leaks media. To make that
//! impossible by construction:
//!   * Inbound decrypt state is keyed per **(source peer, ssrc)** with its own
//!     rollover counter + replay window — one peer can never poison another's
//!     ROC (a cross-peer availability attack) nor bypass replay.
//!   * Outbound re-encrypt state is keyed per **(recipient peer, ssrc)** and
//!     carries its OWN replay window: an index already encrypted to a recipient
//!     is NEVER encrypted again (the packet is dropped), so the outbound nonce
//!     cannot repeat regardless of inbound eviction, SSRC spoofing, or replay.
//!   * The reuse-critical outbound state is tied to the recipient's KEY lifetime:
//!     a peer context is evicted only when its DTLS session is gone or its key
//!     changed (a re-handshake ⇒ a fresh key, so resetting the window is safe).
//!     It is NEVER LRU-recycled while its key is live — an over-full table fails
//!     closed (drops the new stream) rather than resetting a live window.
//!   * SSRC ownership is bound to the first authenticated source; a DTLS peer
//!     that spoofs an SSRC owned by another source is rejected.
//!
//! Fail-closed everywhere: auth failure, replay, an unclaimable SSRC, a full
//! table, or 48-bit index exhaustion all DROP (return null) — never forward
//! unauthenticated or nonce-reusing bytes. The owning media pump is the SOLE
//! thread that touches the hub; there is no internal synchronisation.
const std = @import("std");
const srtp = @import("../proto/srtp.zig");
const srtcp = @import("../proto/srtcp.zig");
const dtls_srtp = @import("../proto/dtls_srtp.zig");
const dtls_server = @import("../proto/dtls12_server.zig");
const ice = @import("../proto/ice.zig");

pub const TransportAddress = ice.TransportAddress;
pub const ExportedKeys = dtls_srtp.ExportedKeys;

/// Per-recipient SRTP overhead the pump must reserve on egress buffers.
pub const rtp_overhead: usize = srtp.auth_tag_len;
/// Per-recipient SRTCP overhead (index word + auth tag) on egress buffers.
pub const rtcp_overhead: usize = srtcp.index_len + srtcp.auth_tag_len;

/// Max simultaneous DTLS-SRTP peers with live crypto contexts. Must be >= the
/// DTLS terminator's session cap so a peer with a LIVE key is never evicted —
/// evicting it would reset its reuse-critical outbound replay windows. An
/// over-full hub fails closed on new peers instead of recycling a live one.
pub const max_peers: usize = dtls_server.default_max_sessions;
comptime {
    std.debug.assert(max_peers >= dtls_server.default_max_sessions);
}

/// Inbound (source) SSRC streams tracked per peer, retained for the key lifetime.
/// Retained ingress capacity follows the existing source-owned SSRC geometry.
/// This is a storage bound, not proof of complete physical graph inventory.
pub const max_in_streams: usize = max_owners;
/// Outbound (recipient) SSRC streams tracked per peer — one per source SSRC the
/// recipient receives. Fail-closed when full (never recycled: recycling would
/// reset a reuse-critical replay window). Sized to the SFU fan-out cap
/// (`media_transport.max_forward` = 64); a recipient fed by more distinct SSRCs
/// than this (a very large multi-stream call) drops the excess streams to it —
/// an availability limit, never a nonce-safety compromise.
pub const max_out_streams: usize = 64;
/// SSRC → owning source bindings (integrity: reject cross-source SSRC spoofing).
pub const max_owners: usize = 256;
/// Replay authority must cover the complete bounded SSRC ownership inventory,
/// rather than the smaller recyclable RTP working set. Never recycle these.
pub const max_srtcp_in_streams: usize = max_owners;

/// 64-index anti-replay window (RFC 3711 §3.3.2), over the 48-bit SRTP index.
const replay_window: u64 = 64;

/// Per-stream rollover-counter + anti-replay state (RFC 3711 §3.3.1 / App. A).
/// Used for BOTH an inbound source stream (guards decrypt replay) and an
/// outbound recipient stream (guards against re-encrypting a repeated index).
const StreamCtx = struct {
    ssrc: u32 = 0,
    active: bool = false,
    last_use: u64 = 0,
    roc: u32 = 0,
    s_l: u16 = 0,
    seen: bool = false,
    replay_top: u64 = 0,
    replay_bits: u64 = 0,

    fn reset(self: *StreamCtx, ssrc: u32, now: u64) void {
        self.* = .{ .ssrc = ssrc, .active = true, .last_use = now };
    }
};

const GuessedIndex = struct { index: u64, roc: u32 };

/// Authenticated ingress replay authority, scoped to one peer key and sender
/// SSRC. Never recycled while that key remains live. Exhaustion of free slots
/// drops a new sender rather than forgetting an accepted replay list.
const SrtcpIngress = struct {
    ssrc: u32 = 0,
    active: bool = false,
    top: u31 = 0,
    bits: u64 = 0,
};

/// Per-peer crypto context. Inbound = client-write keys (decrypt packets FROM
/// this peer, the DTLS client); outbound = server-write keys (encrypt packets TO
/// this peer). Only evicted on session-gone / key-change, never LRU-recycled.
const PeerCtx = struct {
    addr: TransportAddress = .{},
    active: bool = false,
    last_use: u64 = 0,
    /// Exported keying material, retained to detect a re-handshake (key change).
    material: ExportedKeys = std.mem.zeroes(ExportedKeys),
    inbound: srtp.SessionKeys = std.mem.zeroes(srtp.SessionKeys),
    outbound: srtp.SessionKeys = std.mem.zeroes(srtp.SessionKeys),
    /// Monotonic SRTCP egress index (per recipient). Strictly increasing, never
    /// reset for a live key ⇒ the (ssrc, index) SRTCP nonce never repeats.
    /// u32 so 31-bit exhaustion fails closed rather than wrapping into reuse.
    srtcp_out_index: u32 = 0,
    srtcp_in: [max_srtcp_in_streams]SrtcpIngress = @splat(.{}),
    in_streams: [max_in_streams]StreamCtx = @splat(.{}),
    out_streams: [max_out_streams]StreamCtx = @splat(.{}),

    fn wipe(self: *PeerCtx) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.material));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.inbound));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.outbound));
        self.* = .{};
    }
};

/// SSRC → owning source address (first authenticated writer wins).
const OwnerEntry = struct {
    ssrc: u32 = 0,
    addr: TransportAddress = .{},
    active: bool = false,
    last_use: u64 = 0,
};

/// A receipt is an independently captured issuance, not a pointer into a
/// recyclable slot. Actual authentication installs the only canonical pending
/// operation; the receipt alone cannot create or replace that operation.
pub const IngressReceipt = enum(u128) { _ };
pub const PreparedIngress = struct { receipt: IngressReceipt, plain: []const u8 };
const IngressState = union(enum) {
    rtp: struct { slot: usize, old: StreamCtx, next: StreamCtx },
    rtcp: struct { slot: usize, old: SrtcpIngress, next: SrtcpIngress },
};
const PendingIngress = struct {
    issuer: *SfuSrtp,
    receipt: IngressReceipt,
    peers_ptr: usize,
    peers_len: usize,
    peer: usize,
    address: TransportAddress,
    material: ExportedKeys,
    inbound: srtp.SessionKeys,
    old_peer_use: u64,
    owner: usize,
    old_owner: OwnerEntry,
    next_owner: OwnerEntry,
    clock: u64,
    next_clock: u64,
    state: IngressState,
    plain: []const u8,
    digest: [32]u8,
};
var next_ingress_source = std.atomic.Value(u64).init(1);
fn ingressSourceIdentity() ?u64 {
    var old = next_ingress_source.load(.monotonic);
    while (old != 0 and old != std.math.maxInt(u64)) {
        if (next_ingress_source.cmpxchgWeak(old, old + 1, .monotonic, .monotonic)) |changed| {
            old = changed;
        } else return old;
    }
    return null;
}
fn ingressPlainDigest(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

pub const SfuSrtp = struct {
    allocator: std.mem.Allocator,
    /// Lazily allocated (on first established peer) so DTLS-off servers pay
    /// nothing; freed by `wipe`.
    peers: []PeerCtx = &.{},
    owners: [max_owners]OwnerEntry = @splat(.{}),
    clock: u64 = 0,
    ingress_source: u64 = 0,
    next_ingress: u64 = 1,
    pending_ingress: ?PendingIngress = null,

    /// Owned source DTO. The authenticated aggregate must additionally join each
    /// active peer/material to the restored DTLS owner before publication. This
    /// representation is not a wire codec or an independent authentication proof.
    pub const Snapshot = struct {
        pub const Stream = StreamCtx;
        pub const Owner = OwnerEntry;
        pub const Peer = struct {
            addr: TransportAddress = .{},
            active: bool = false,
            last_use: u64 = 0,
            material: ExportedKeys = std.mem.zeroes(ExportedKeys),
            srtcp_out_index: u32 = 0,
            srtcp_in: [max_srtcp_in_streams]SrtcpIngress = @splat(.{}),
            in_streams: [max_in_streams]Stream = @splat(.{}),
            out_streams: [max_out_streams]Stream = @splat(.{}),
        };
        allocator: std.mem.Allocator,
        peers: []Peer,
        owners: [max_owners]Owner,
        clock: u64,

        pub fn deinit(self: *Snapshot) void {
            for (self.peers) |*peer| std.crypto.secureZero(u8, std.mem.asBytes(&peer.material));
            self.allocator.free(self.peers);
            self.* = undefined;
        }

        fn validAddress(addr: TransportAddress) bool {
            if ((addr.ip_len != 4 and addr.ip_len != 16) or addr.port == 0) return false;
            for (addr.ip[addr.ip_len..]) |byte| if (byte != 0) return false;
            return true;
        }

        fn validateStreams(streams: []const Stream) !void {
            for (streams, 0..) |stream, i| {
                if (!stream.active) {
                    if (!std.meta.eql(stream, Stream{})) return error.InvalidSnapshot;
                    continue;
                }
                if (!stream.seen) {
                    if (stream.roc != 0 or stream.s_l != 0 or stream.replay_top != 0 or stream.replay_bits != 0) return error.InvalidSnapshot;
                } else {
                    if (stream.replay_top > std.math.maxInt(u48) or stream.replay_bits & 1 == 0 or
                        stream.replay_top != (@as(u64, stream.roc) << 16) | stream.s_l) return error.InvalidSnapshot;
                }
                for (streams[0..i]) |prior| if (prior.active and prior.ssrc == stream.ssrc) return error.InvalidSnapshot;
            }
        }

        fn requireIngressOwner(self: *const Snapshot, ssrc: u32, addr: TransportAddress) !void {
            for (self.owners) |owner| {
                if (owner.active and owner.ssrc == ssrc) {
                    if (!owner.addr.eql(addr)) return error.InvalidSnapshot;
                    return;
                }
            }
            return error.InvalidSnapshot;
        }

        pub fn validate(self: *const Snapshot) !void {
            if (self.peers.len != 0 and self.peers.len != max_peers) return error.InvalidSnapshot;
            for (self.peers, 0..) |peer, i| {
                if (!peer.active) {
                    if (!std.meta.eql(peer, Peer{})) return error.InvalidSnapshot;
                    continue;
                }
                if (!validAddress(peer.addr) or peer.srtcp_out_index > @as(u32, std.math.maxInt(u31)) + 1) return error.InvalidSnapshot;
                for (peer.srtcp_in, 0..) |context, j| {
                    if (!context.active) {
                        if (!std.meta.eql(context, SrtcpIngress{})) return error.InvalidSnapshot;
                        continue;
                    }
                    if (context.bits & 1 == 0) return error.InvalidSnapshot;
                    // Indices below zero cannot have been received.
                    if (context.top < 63 and context.bits >> @as(u6, @intCast(context.top + 1)) != 0) return error.InvalidSnapshot;
                    for (peer.srtcp_in[0..j]) |prior| if (prior.active and prior.ssrc == context.ssrc) return error.InvalidSnapshot;
                }
                try validateStreams(&peer.in_streams);
                try validateStreams(&peer.out_streams);
                for (self.peers[0..i]) |prior| if (prior.active and prior.addr.eql(peer.addr)) return error.InvalidSnapshot;
            }
            for (self.owners, 0..) |owner, i| {
                if (!owner.active) {
                    if (!std.meta.eql(owner, Owner{})) return error.InvalidSnapshot;
                    continue;
                }
                if (!validAddress(owner.addr)) return error.InvalidSnapshot;
                var found = false;
                for (self.peers) |peer| if (peer.active and peer.addr.eql(owner.addr)) {
                    for (peer.in_streams) |stream| if (stream.active and stream.seen and stream.ssrc == owner.ssrc) {
                        found = true;
                        break;
                    };
                    if (!found) for (peer.srtcp_in) |context| if (context.active and context.ssrc == owner.ssrc) {
                        found = true;
                        break;
                    };
                    break;
                };
                if (!found) return error.InvalidSnapshot;
                for (self.owners[0..i]) |prior| if (prior.active and prior.ssrc == owner.ssrc) return error.InvalidSnapshot;
            }
            // Only authenticated accepted ingress claims an SSRC. Outbound
            // recipient histories intentionally have no corresponding owner
            // requirement: they belong to a different key/nonce direction.
            for (self.peers) |peer| {
                if (!peer.active) continue;
                for (peer.in_streams) |stream| {
                    if (stream.active and stream.seen) try self.requireIngressOwner(stream.ssrc, peer.addr);
                }
                for (peer.srtcp_in) |context| {
                    if (context.active) try self.requireIngressOwner(context.ssrc, peer.addr);
                }
            }
            // Preserve the actual LRU clock and all stamps, including the
            // existing wrapping-clock semantics. Neither restores nonce state.
        }
    };

    pub fn capture(self: *const SfuSrtp, allocator: std.mem.Allocator) !Snapshot {
        if (self.pending_ingress != null) return error.Busy;
        if (self.peers.len != 0 and self.peers.len != max_peers) return error.InvalidSnapshot;
        const peers = try allocator.alloc(Snapshot.Peer, self.peers.len);
        errdefer {
            for (peers) |*peer| std.crypto.secureZero(u8, std.mem.asBytes(&peer.material));
            allocator.free(peers);
        }
        for (peers) |*peer| peer.* = .{};
        for (self.peers, peers) |source, *dest| {
            if (source.active) {
                var inbound = srtp.deriveSessionKeys(source.material.clientMaster(), source.material.clientSalt());
                defer std.crypto.secureZero(u8, std.mem.asBytes(&inbound));
                var outbound = srtp.deriveSessionKeys(source.material.serverMaster(), source.material.serverSalt());
                defer std.crypto.secureZero(u8, std.mem.asBytes(&outbound));
                if (!std.meta.eql(inbound, source.inbound) or !std.meta.eql(outbound, source.outbound)) return error.InvalidSnapshot;
            } else if (!std.meta.eql(source, PeerCtx{})) return error.InvalidSnapshot;
            dest.* = .{ .addr = source.addr, .active = source.active, .last_use = source.last_use, .material = source.material, .srtcp_out_index = source.srtcp_out_index, .srtcp_in = source.srtcp_in, .in_streams = source.in_streams, .out_streams = source.out_streams };
        }
        const snapshot: Snapshot = .{ .allocator = allocator, .peers = peers, .owners = self.owners, .clock = self.clock };
        try snapshot.validate();
        return snapshot;
    }

    pub fn prepareRestore(allocator: std.mem.Allocator, snapshot: *const Snapshot) !SfuSrtp {
        try snapshot.validate();
        var candidate = init(allocator);
        const peers = try allocator.alloc(PeerCtx, snapshot.peers.len);
        for (peers, snapshot.peers) |*dest, source| {
            dest.* = .{ .addr = source.addr, .active = source.active, .last_use = source.last_use, .material = source.material, .srtcp_out_index = source.srtcp_out_index, .srtcp_in = source.srtcp_in, .in_streams = source.in_streams, .out_streams = source.out_streams };
            if (source.active) {
                dest.inbound = srtp.deriveSessionKeys(source.material.clientMaster(), source.material.clientSalt());
                dest.outbound = srtp.deriveSessionKeys(source.material.serverMaster(), source.material.serverSalt());
            }
        }
        candidate.peers = peers;
        candidate.owners = snapshot.owners;
        candidate.clock = snapshot.clock;
        return candidate;
    }

    pub fn init(allocator: std.mem.Allocator) SfuSrtp {
        return .{ .allocator = allocator };
    }

    fn tick(self: *SfuSrtp) u64 {
        self.clock +%= 1;
        return self.clock;
    }

    fn ensurePeers(self: *SfuSrtp) bool {
        if (self.peers.len != 0) return true;
        const p = self.allocator.alloc(PeerCtx, max_peers) catch return false;
        for (p) |*e| e.* = .{};
        self.peers = p;
        return true;
    }

    // -- peer table --------------------------------------------------------

    fn findPeer(self: *SfuSrtp, addr: TransportAddress) ?*PeerCtx {
        for (self.peers) |*p| {
            if (p.active and p.addr.eql(addr)) return p;
        }
        return null;
    }

    fn materialEql(a: *const ExportedKeys, b: *const ExportedKeys) bool {
        return std.mem.eql(u8, std.mem.asBytes(a), std.mem.asBytes(b));
    }

    /// Install (idempotently) the live SRTP contexts for a DTLS-SRTP peer.
    /// Returns false when the table is full of live peers (fail closed — the
    /// caller drops that leg rather than recycling a live context). A changed
    /// key (re-handshake at the same address) reinstalls with a fresh key and
    /// fresh — safely reset — replay windows.
    pub fn noteEstablished(self: *SfuSrtp, addr: TransportAddress, exported: ExportedKeys) bool {
        if (self.pending_ingress != null) return false;
        if (!self.ensurePeers()) return false;
        if (self.findPeer(addr)) |p| {
            if (materialEql(&p.material, &exported)) {
                p.last_use = self.tick();
                return true;
            }
            self.releaseOwnedBy(addr); // old streams retired with the old key
            p.wipe();
            self.installPeer(p, addr, exported);
            return true;
        }
        // New peer: use only a FREE slot — never recycle a live one.
        for (self.peers) |*p| {
            if (!p.active) {
                self.installPeer(p, addr, exported);
                return true;
            }
        }
        return false; // full of live peers ⇒ fail closed
    }

    fn installPeer(self: *SfuSrtp, p: *PeerCtx, addr: TransportAddress, exported: ExportedKeys) void {
        p.addr = addr;
        p.material = exported;
        p.inbound = srtp.deriveSessionKeys(exported.clientMaster(), exported.clientSalt());
        p.outbound = srtp.deriveSessionKeys(exported.serverMaster(), exported.serverSalt());
        p.srtcp_out_index = 0;
        p.srtcp_in = @splat(.{});
        for (&p.in_streams) |*s| s.* = .{};
        for (&p.out_streams) |*s| s.* = .{};
        p.active = true;
        p.last_use = self.tick();
    }

    /// Whether a live crypto context exists for `addr`.
    /// Read-only join used after the actual DTLS operation installed keys.
    /// A rejected media packet must not tick accepted state merely to recheck.
    pub fn peerMaterialMatches(self: *const SfuSrtp, addr: TransportAddress, material: ExportedKeys) bool {
        for (self.peers) |*peer| if (peer.active and peer.addr.eql(addr)) return materialEql(&peer.material, &material);
        return false;
    }

    pub fn peerActive(self: *SfuSrtp, addr: TransportAddress) bool {
        return self.findPeer(addr) != null;
    }

    /// Drop a peer's crypto context (secure-zeroing its keys) and release its
    /// SSRC ownerships. Safe for an unknown address.
    pub fn evict(self: *SfuSrtp, addr: TransportAddress) void {
        std.debug.assert(self.pending_ingress == null);
        self.releaseOwnedBy(addr);
        if (self.findPeer(addr)) |p| p.wipe();
    }

    // -- SSRC ownership ----------------------------------------------------

    /// Whether `ssrc` is currently owned by a source OTHER than `addr`.
    fn ssrcOwnedByOther(self: *SfuSrtp, ssrc: u32, addr: TransportAddress) bool {
        for (&self.owners) |*o| {
            if (o.active and o.ssrc == ssrc) return !o.addr.eql(addr);
        }
        return false;
    }

    /// Reserve an existing same-owner or FREE slot without publishing state.
    /// Never recycle a live claim while its key/session remains installed.
    fn ownerSlot(self: *SfuSrtp, ssrc: u32, addr: TransportAddress) ?*OwnerEntry {
        var free: ?*OwnerEntry = null;
        for (&self.owners) |*o| {
            if (o.active and o.ssrc == ssrc) return if (o.addr.eql(addr)) o else null;
            if (!o.active and free == null) free = o;
        }
        return free;
    }

    fn claimSsrc(self: *SfuSrtp, slot: *OwnerEntry, ssrc: u32, addr: TransportAddress) void {
        slot.* = .{ .ssrc = ssrc, .addr = addr, .active = true, .last_use = self.tick() };
    }

    fn releaseOwnedBy(self: *SfuSrtp, addr: TransportAddress) void {
        for (&self.owners) |*o| {
            if (o.active and o.addr.eql(addr)) o.* = .{};
        }
    }

    // -- per-peer stream slots ---------------------------------------------

    /// Borrow an existing or FREE ingress slot; no recency/replay mutation.
    fn inStream(p: *PeerCtx, ssrc: u32) ?*StreamCtx {
        var free: ?*StreamCtx = null;
        for (&p.in_streams) |*s| {
            if (s.active and s.ssrc == ssrc) return s;
            if (!s.active and free == null) free = s;
        }
        return free;
    }

    /// Outbound recipient stream for `ssrc`. Fail-closed when full: NEVER
    /// recycles a live stream (that would reset its reuse-critical window).
    fn outStream(self: *SfuSrtp, p: *PeerCtx, ssrc: u32) ?*StreamCtx {
        const now = self.tick();
        for (&p.out_streams) |*s| {
            if (s.active and s.ssrc == ssrc) {
                s.last_use = now;
                return s;
            }
        }
        for (&p.out_streams) |*s| {
            if (!s.active) {
                s.reset(ssrc, now);
                return s;
            }
        }
        return null; // full ⇒ fail closed
    }

    // -- SRTP packet index (RFC 3711 §3.3.1 / Appendix A) ------------------

    /// Estimate the 48-bit SRTP index for a received `seq` WITHOUT committing,
    /// so a packet that fails a later check cannot advance the ROC.
    fn guess(s: *const StreamCtx, seq: u16) GuessedIndex {
        if (!s.seen) return .{ .index = seq, .roc = 0 };
        const s_l: i64 = s.s_l;
        const sq: i64 = seq;
        var v: i64 = s.roc;
        if (s.s_l < 0x8000) {
            if (sq - s_l > 0x8000) v = @as(i64, s.roc) - 1;
        } else {
            if (s_l - sq > 0x8000) v = @as(i64, s.roc) + 1;
        }
        if (v < 0) v = 0; // pre-start reorder guard (ROC 0 has no predecessor)
        const roc: u32 = @intCast(v & 0xFFFF_FFFF);
        return .{ .index = (@as(u64, roc) << 16) | seq, .roc = roc };
    }

    /// Advance ROC / highest-sequence after an ACCEPTED (authenticated or
    /// successfully-encrypted) packet.
    fn commit(s: *StreamCtx, g: GuessedIndex, seq: u16) void {
        if (!s.seen) {
            s.seen = true;
            s.roc = g.roc;
            s.s_l = seq;
        } else if (g.roc == s.roc) {
            if (seq > s.s_l) s.s_l = seq;
        } else if (g.roc == s.roc +% 1) {
            s.roc = g.roc;
            s.s_l = seq;
        }
        markSeen(s, g.index);
    }

    fn isSeen(s: *const StreamCtx, index: u64) bool {
        if (!s.seen) return false;
        if (index > s.replay_top) return false;
        const diff = s.replay_top - index;
        if (diff >= replay_window) return true; // outside the window ⇒ too old
        return (s.replay_bits >> @intCast(diff)) & 1 == 1;
    }

    fn markSeen(s: *StreamCtx, index: u64) void {
        if (index > s.replay_top) {
            const shift = index - s.replay_top;
            s.replay_bits = if (shift >= 64) 0 else s.replay_bits << @intCast(shift);
            s.replay_bits |= 1; // bit 0 tracks the new top
            s.replay_top = index;
        } else {
            const diff = s.replay_top - index;
            if (diff < 64) s.replay_bits |= (@as(u64, 1) << @intCast(diff));
        }
    }

    // -- inbound (decrypt from a DTLS-SRTP peer) ---------------------------

    /// Decrypt an inbound SRTP packet from DTLS-SRTP peer `addr` into `out`.
    /// Null (⇒ DROP) if the peer is unknown, the SSRC is owned by another
    /// source, the packet is replayed, or the auth tag fails. ROC/replay and
    /// SSRC ownership advance ONLY after successful authentication.
    ///
    /// The SSRC and sequence are read from the packet's OWN (cleartext) RTP
    /// header — the SAME bytes `srtp.unprotect` builds the AES-CM nonce from — so
    /// the replay-window key and the decryption nonce can never diverge.
    pub fn unprotectRtp(self: *SfuSrtp, addr: TransportAddress, packet: []const u8, out: []u8) ?[]const u8 {
        const prepared = self.prepareIngressRtp(addr, packet, out) orelse return null;
        self.validateIngress(prepared.receipt) catch {
            self.abortIngress(prepared.receipt) catch unreachable;
            return null;
        };
        self.commitIngress(prepared.receipt);
        return prepared.plain;
    }

    /// Decrypts without publishing accepted replay, ownership, recency or ROC.
    /// The owning pump retains this fixed pending slot while it parses canonical
    /// bytes and prepares all fallible cache storage. No heap clone or reset.
    pub fn prepareIngressRtp(self: *SfuSrtp, addr: TransportAddress, packet: []const u8, out: []u8) ?PreparedIngress {
        if (self.pending_ingress != null or self.next_ingress == 0 or self.next_ingress == std.math.maxInt(u64) or packet.len < srtp.rtp_header_len) return null;
        const ssrc = std.mem.readInt(u32, packet[8..12], .big);
        const seq = std.mem.readInt(u16, packet[2..4], .big);
        const p = self.findPeer(addr) orelse return null;
        const owner = self.ownerSlot(ssrc, addr) orelse return null;
        const slot = inStream(p, ssrc) orelse return null;
        var tentative = slot.*;
        if (!tentative.active) tentative.reset(ssrc, 0);
        const guessed = guess(&tentative, seq);
        if (isSeen(&tentative, guessed.index)) return null;
        const plain = srtp.unprotect(p.inbound, guessed.roc, packet, out) catch return null;
        const identity = if (self.ingress_source != 0) self.ingress_source else ingressSourceIdentity() orelse return null;
        commit(&tentative, guessed, seq);
        tentative.last_use = self.clock +% 2;
        return self.installIngress(identity, p, owner, ssrc, plain, .{ .rtp = .{ .slot = (@intFromPtr(slot) - @intFromPtr(&p.in_streams[0])) / @sizeOf(StreamCtx), .old = slot.*, .next = tentative } }, 3);
    }

    pub fn unprotectRtcp(self: *SfuSrtp, addr: TransportAddress, packet: []const u8, out: []u8) ?[]const u8 {
        const prepared = self.prepareIngressRtcp(addr, packet, out) orelse return null;
        self.validateIngress(prepared.receipt) catch {
            self.abortIngress(prepared.receipt) catch unreachable;
            return null;
        };
        self.commitIngress(prepared.receipt);
        return prepared.plain;
    }

    /// Authenticates SRTCP before reserving a per-SSRC tentative replay row.
    /// Strict compound parsing must finish before the source publishes this row.
    pub fn prepareIngressRtcp(self: *SfuSrtp, addr: TransportAddress, packet: []const u8, out: []u8) ?PreparedIngress {
        if (self.pending_ingress != null or self.next_ingress == 0 or self.next_ingress == std.math.maxInt(u64)) return null;
        const p = self.findPeer(addr) orelse return null;
        const plain = srtcp.unprotect(p.inbound, packet, out) catch return null;
        const ssrc = std.mem.readInt(u32, plain[4..8], .big);
        const owner = self.ownerSlot(ssrc, addr) orelse return null;
        const index: u31 = @intCast(std.mem.readInt(u32, packet[plain.len..][0..srtcp.index_len], .big) & 0x7fff_ffff);
        var selected: ?*SrtcpIngress = null;
        var free: ?*SrtcpIngress = null;
        for (&p.srtcp_in) |*context| {
            if (context.active and context.ssrc == ssrc) {
                selected = context;
                break;
            }
            if (!context.active and free == null) free = context;
        }
        const slot = selected orelse free orelse return null;
        var tentative = slot.*;
        if (tentative.active) {
            if (index <= tentative.top) {
                const distance = tentative.top - index;
                if (distance >= 64 or tentative.bits >> @as(u6, @intCast(distance)) & 1 != 0) return null;
                tentative.bits |= @as(u64, 1) << @as(u6, @intCast(distance));
            } else {
                const distance = index - tentative.top;
                tentative.bits = (if (distance >= 64) @as(u64, 0) else tentative.bits << @as(u6, @intCast(distance))) | 1;
                tentative.top = index;
            }
        } else tentative = .{ .active = true, .ssrc = ssrc, .top = index, .bits = 1 };
        const identity = if (self.ingress_source != 0) self.ingress_source else ingressSourceIdentity() orelse return null;
        return self.installIngress(identity, p, owner, ssrc, plain, .{ .rtcp = .{ .slot = (@intFromPtr(slot) - @intFromPtr(&p.srtcp_in[0])) / @sizeOf(SrtcpIngress), .old = slot.*, .next = tentative } }, 2);
    }

    fn installIngress(self: *SfuSrtp, identity: u64, p: *PeerCtx, owner: *OwnerEntry, ssrc: u32, plain: []const u8, state: IngressState, ticks: u64) PreparedIngress {
        std.debug.assert(self.pending_ingress == null and identity != 0 and self.next_ingress != 0 and self.next_ingress != std.math.maxInt(u64));
        const receipt: IngressReceipt = @enumFromInt((@as(u128, identity) << 64) | self.next_ingress);
        self.ingress_source = identity;
        self.next_ingress += 1;
        self.pending_ingress = .{ .issuer = self, .receipt = receipt, .peers_ptr = @intFromPtr(self.peers.ptr), .peers_len = self.peers.len, .peer = (@intFromPtr(p) - @intFromPtr(self.peers.ptr)) / @sizeOf(PeerCtx), .address = p.addr, .material = p.material, .inbound = p.inbound, .old_peer_use = p.last_use, .owner = (@intFromPtr(owner) - @intFromPtr(&self.owners[0])) / @sizeOf(OwnerEntry), .old_owner = owner.*, .next_owner = .{ .ssrc = ssrc, .addr = p.addr, .active = true, .last_use = self.clock +% 1 }, .clock = self.clock, .next_clock = self.clock +% ticks, .state = state, .plain = plain, .digest = ingressPlainDigest(plain) };
        return .{ .receipt = receipt, .plain = plain };
    }

    /// Exact original source/slot/key/accepted-state and canonical-byte join.
    /// No allocator call; an expired or foreign receipt cannot select a slot.
    pub fn validateIngress(self: *const SfuSrtp, receipt: IngressReceipt) error{StaleIngress}!void {
        const pending = self.pending_ingress orelse return error.StaleIngress;
        if (pending.issuer != self or pending.receipt != receipt or pending.peers_ptr != @intFromPtr(self.peers.ptr) or pending.peers_len != self.peers.len or pending.peer >= self.peers.len or pending.owner >= self.owners.len or self.clock != pending.clock or !std.meta.eql(self.owners[pending.owner], pending.old_owner)) return error.StaleIngress;
        const peer = &self.peers[pending.peer];
        if (!peer.active or !peer.addr.eql(pending.address) or !materialEql(&peer.material, &pending.material) or !std.meta.eql(peer.inbound, pending.inbound) or peer.last_use != pending.old_peer_use or !std.mem.eql(u8, &pending.digest, &ingressPlainDigest(pending.plain))) return error.StaleIngress;
        switch (pending.state) {
            .rtp => |state| if (state.slot >= peer.in_streams.len or !std.meta.eql(peer.in_streams[state.slot], state.old)) return error.StaleIngress,
            .rtcp => |state| if (state.slot >= peer.srtcp_in.len or !std.meta.eql(peer.srtcp_in[state.slot], state.old)) return error.StaleIngress,
        }
    }
    pub fn commitIngress(self: *SfuSrtp, receipt: IngressReceipt) void {
        self.validateIngress(receipt) catch @panic("SFU ingress publication requires exact validated source receipt");
        const pending = &self.pending_ingress.?;
        const peer = &self.peers[pending.peer];
        switch (pending.state) {
            .rtp => |state| peer.in_streams[state.slot] = state.next,
            .rtcp => |state| peer.srtcp_in[state.slot] = state.next,
        }
        self.owners[pending.owner] = pending.next_owner;
        peer.last_use = pending.next_clock;
        self.clock = pending.next_clock;
        self.clearIngress();
    }
    pub fn abortIngress(self: *SfuSrtp, receipt: IngressReceipt) error{StaleIngress}!void {
        const pending = self.pending_ingress orelse return error.StaleIngress;
        if (pending.issuer != self or pending.receipt != receipt) return error.StaleIngress;
        self.clearIngress();
    }
    fn clearIngress(self: *SfuSrtp) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.pending_ingress.?));
        self.pending_ingress = null;
    }

    // -- outbound (re-encrypt to a DTLS-SRTP peer) -------------------------

    /// Re-encrypt plaintext RTP for DTLS-SRTP recipient `addr` under its own
    /// outbound key. The per-(recipient, ssrc) replay window guarantees the
    /// (ssrc, index) nonce is NEVER used twice for this recipient — a repeated
    /// index is refused (null). Null ⇒ unknown recipient, out-of-slots (fail
    /// closed), nonce already used, or a protect error.
    ///
    /// The SSRC and sequence are read from `plain`'s OWN RTP header — the SAME
    /// bytes `srtp.protect` builds the AES-CM nonce from — so the replay-window
    /// key and the encryption nonce can NEVER diverge. This is what keeps the
    /// retransmit (NACK) path safe: the caller cannot pass a mismatched SSRC that
    /// would advance a different window than the nonce actually uses.
    pub fn protectRtp(self: *SfuSrtp, addr: TransportAddress, plain: []const u8, out: []u8) ?[]const u8 {
        if (self.pending_ingress != null) return null;
        if (plain.len < srtp.rtp_header_len) return null;
        const ssrc = std.mem.readInt(u32, plain[8..12], .big);
        const seq = std.mem.readInt(u16, plain[2..4], .big);
        const p = self.findPeer(addr) orelse return null;
        const s = self.outStream(p, ssrc) orelse return null;
        const g = guess(s, seq);
        if (isSeen(s, g.index)) return null; // nonce already used ⇒ refuse (no two-time-pad)
        const wire = srtp.protect(p.outbound, g.roc, plain, out) catch return null;
        commit(s, g, seq);
        p.last_use = self.tick();
        return wire;
    }

    /// Re-encrypt plaintext RTCP for DTLS-SRTP recipient `addr` under its own
    /// outbound key with the next monotonic SRTCP index. Null ⇒ unknown
    /// recipient, 31-bit index exhaustion (fail closed — never a reused nonce),
    /// or a protect error.
    pub fn protectRtcp(self: *SfuSrtp, addr: TransportAddress, plain: []const u8, out: []u8) ?[]const u8 {
        if (self.pending_ingress != null) return null;
        const p = self.findPeer(addr) orelse return null;
        const idx = p.srtcp_out_index;
        if (idx > std.math.maxInt(u31)) return null; // exhausted
        const wire = srtcp.protect(p.outbound, @intCast(idx), plain, out) catch return null;
        p.srtcp_out_index = idx + 1;
        p.last_use = self.tick();
        return wire;
    }

    /// Snapshot the addresses of every live peer context into `out` (for the
    /// pump to reconcile against the terminator and evict departed peers).
    /// Returns how many were written.
    pub fn activePeerAddrs(self: *SfuSrtp, out: []TransportAddress) usize {
        var n: usize = 0;
        for (self.peers) |*p| {
            if (!p.active) continue;
            if (n >= out.len) break;
            out[n] = p.addr;
            n += 1;
        }
        return n;
    }

    /// Secure-zero every live key, free the peer table, and reset all state
    /// (call on teardown, with the pump stopped).
    pub fn wipe(self: *SfuSrtp) void {
        std.debug.assert(self.pending_ingress == null);
        for (self.peers) |*p| {
            std.crypto.secureZero(u8, std.mem.asBytes(&p.material));
            std.crypto.secureZero(u8, std.mem.asBytes(&p.inbound));
            std.crypto.secureZero(u8, std.mem.asBytes(&p.outbound));
        }
        if (self.peers.len != 0) self.allocator.free(self.peers);
        self.peers = &.{};
        self.owners = @splat(.{});
        self.clock = 0;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn mkAddr(last: u8) TransportAddress {
    return TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, last }, 5000 + @as(u16, last)) catch unreachable;
}

/// Synthetic per-peer exported keying material (as if from a distinct DTLS
/// handshake): client-write and server-write differ, and each peer differs.
fn mkKeys(seed: u8) ExportedKeys {
    var e: ExportedKeys = undefined;
    for (&e.client, 0..) |*b, i| b.* = @intCast((i *% 7 +% seed) & 0xff);
    for (&e.server, 0..) |*b, i| b.* = @intCast((i *% 13 +% seed +% 128) & 0xff);
    return e;
}

/// A minimal RTP packet: V2, PT96, given seq/ssrc, then `payload`.
fn rtpPacket(seq: u16, ssrc: u32, payload: []const u8, out: []u8) []const u8 {
    out[0] = 0x80;
    out[1] = 0x60;
    std.mem.writeInt(u16, out[2..4], seq, .big);
    std.mem.writeInt(u32, out[4..8], 0x0000_0064, .big); // timestamp
    std.mem.writeInt(u32, out[8..12], ssrc, .big);
    @memcpy(out[12..][0..payload.len], payload);
    return out[0 .. 12 + payload.len];
}

test "SFU forward: source decrypted, re-encrypted to two peers under distinct keys" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();

    const kA = mkKeys(1);
    const kB = mkKeys(2);
    const kC = mkKeys(3);
    const aA = mkAddr(1);
    const aB = mkAddr(2);
    const aC = mkAddr(3);
    try testing.expect(hub.noteEstablished(aA, kA));
    try testing.expect(hub.noteEstablished(aB, kB));
    try testing.expect(hub.noteEstablished(aC, kC));

    const ssrc: u32 = 0xCAFE_BABE;
    const seq: u16 = 0x2a;
    var rtp_buf: [64]u8 = undefined;
    const rtp = rtpPacket(seq, ssrc, "voice-frame", &rtp_buf);

    // A (the DTLS client) protects its egress with the client-write context.
    const a_in = srtp.deriveSessionKeys(kA.clientMaster(), kA.clientSalt());
    var wire_buf: [128]u8 = undefined;
    const wireA = try srtp.protect(a_in, 0, rtp, &wire_buf);

    // Hub decrypts A's inbound, recovering the plaintext RTP verbatim.
    var plain_buf: [128]u8 = undefined;
    const canonical = hub.unprotectRtp(aA, wireA, &plain_buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, rtp, canonical);

    // Re-encrypt to B and C under each recipient's OWN outbound key.
    var toB_buf: [128]u8 = undefined;
    var toC_buf: [128]u8 = undefined;
    const toB = hub.protectRtp(aB, canonical, &toB_buf) orelse return error.TestUnexpectedResult;
    const toC = hub.protectRtp(aC, canonical, &toC_buf) orelse return error.TestUnexpectedResult;
    try testing.expect(!std.mem.eql(u8, toB, toC));

    // B recovers the frame with B's server-write context; C with C's.
    const b_out = srtp.deriveSessionKeys(kB.serverMaster(), kB.serverSalt());
    const c_out = srtp.deriveSessionKeys(kC.serverMaster(), kC.serverSalt());
    var rec: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, rtp, try srtp.unprotect(b_out, 0, toB, &rec));
    try testing.expectEqualSlices(u8, rtp, try srtp.unprotect(c_out, 0, toC, &rec));

    // A's keys can open neither B's packet.
    const a_out = srtp.deriveSessionKeys(kA.serverMaster(), kA.serverSalt());
    try testing.expectError(error.AuthFailed, srtp.unprotect(a_in, 0, toB, &rec));
    try testing.expectError(error.AuthFailed, srtp.unprotect(a_out, 0, toB, &rec));
}

test "SFU bridge: group-key<->DTLS-SRTP both directions carry intelligible media" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();

    const kD = mkKeys(9);
    const aD = mkAddr(4); // the DTLS-SRTP peer
    try testing.expect(hub.noteEstablished(aD, kD));

    // (1) group-key/plaintext source -> DTLS-SRTP recipient. No inbound context
    // is needed; the outbound stream tracks the ROC from the forwarded seq.
    const p_ssrc: u32 = 0x1111_2222;
    const p_seq: u16 = 100;
    var g_buf: [64]u8 = undefined;
    const g_rtp = rtpPacket(p_seq, p_ssrc, "from-group-key", &g_buf);
    var enc_buf: [128]u8 = undefined;
    const to_dtls = hub.protectRtp(aD, g_rtp, &enc_buf) orelse return error.TestUnexpectedResult;
    const d_out = srtp.deriveSessionKeys(kD.serverMaster(), kD.serverSalt());
    var rec: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, g_rtp, try srtp.unprotect(d_out, 0, to_dtls, &rec));

    // (2) DTLS-SRTP source -> group-key recipient (receives the plaintext).
    const d_ssrc: u32 = 0x3333_4444;
    const d_seq: u16 = 55;
    var d_buf: [64]u8 = undefined;
    const d_rtp = rtpPacket(d_seq, d_ssrc, "from-dtls-peer", &d_buf);
    const d_in = srtp.deriveSessionKeys(kD.clientMaster(), kD.clientSalt());
    var wire_buf: [128]u8 = undefined;
    const d_wire = try srtp.protect(d_in, 0, d_rtp, &wire_buf);
    var plain_buf: [128]u8 = undefined;
    const canonical = hub.unprotectRtp(aD, d_wire, &plain_buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, d_rtp, canonical);
}

test "SFU SRTCP: inbound decrypt then per-recipient re-encrypt round-trips" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();

    const kA = mkKeys(5);
    const kB = mkKeys(6);
    const aA = mkAddr(7);
    const aB = mkAddr(8);
    try testing.expect(hub.noteEstablished(aA, kA));
    try testing.expect(hub.noteEstablished(aB, kB));

    const rtcp = [_]u8{ 0x80, 0xC8, 0x00, 0x06, 0xCA, 0xFE, 0xBA, 0xBE } ++ "sr-report-body!!".*;
    const a_in = srtp.deriveSessionKeys(kA.clientMaster(), kA.clientSalt());
    var wire_buf: [128]u8 = undefined;
    const a_wire = try srtcp.protect(a_in, 7, &rtcp, &wire_buf);

    var plain_buf: [128]u8 = undefined;
    const canonical = hub.unprotectRtcp(aA, a_wire, &plain_buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &rtcp, canonical);

    var enc_buf: [128]u8 = undefined;
    const to_b = hub.protectRtcp(aB, canonical, &enc_buf) orelse return error.TestUnexpectedResult;
    const b_out = srtp.deriveSessionKeys(kB.serverMaster(), kB.serverSalt());
    var rec: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, &rtcp, try srtcp.unprotect(b_out, to_b, &rec));

    // Monotonic SRTCP index: a second egress packet uses a fresh index word.
    var enc_buf2: [128]u8 = undefined;
    const to_b2 = hub.protectRtcp(aB, canonical, &enc_buf2) orelse return error.TestUnexpectedResult;
    try testing.expect(!std.mem.eql(u8, to_b, to_b2));
}

test "SFU fail-closed: tampered and replayed inbound packets are dropped" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();

    const kA = mkKeys(4);
    const aA = mkAddr(9);
    try testing.expect(hub.noteEstablished(aA, kA));

    const ssrc: u32 = 0xDEAD_BEEF;
    const seq: u16 = 7;
    var rtp_buf: [64]u8 = undefined;
    const rtp = rtpPacket(seq, ssrc, "secret", &rtp_buf);
    const a_in = srtp.deriveSessionKeys(kA.clientMaster(), kA.clientSalt());
    var wire_buf: [128]u8 = undefined;
    const wireA = try srtp.protect(a_in, 0, rtp, &wire_buf);

    // Tampered ciphertext ⇒ auth failure ⇒ drop. The ROC must NOT move.
    var tampered: [128]u8 = undefined;
    @memcpy(tampered[0..wireA.len], wireA);
    tampered[12] ^= 0x01;
    var out: [128]u8 = undefined;
    try testing.expect(hub.unprotectRtp(aA, tampered[0..wireA.len], &out) == null);

    // The genuine packet still decrypts (forgery did not desync).
    try testing.expectEqualSlices(u8, rtp, hub.unprotectRtp(aA, wireA, &out) orelse return error.TestUnexpectedResult);

    // Replay of the same authenticated packet ⇒ dropped.
    var out2: [128]u8 = undefined;
    try testing.expect(hub.unprotectRtp(aA, wireA, &out2) == null);

    // A fresh higher sequence is still accepted.
    var next_buf: [64]u8 = undefined;
    const next = rtpPacket(seq + 1, ssrc, "secret", &next_buf);
    var nwire_buf: [128]u8 = undefined;
    const nwire = try srtp.protect(a_in, 0, next, &nwire_buf);
    try testing.expect(hub.unprotectRtp(aA, nwire, &out2) != null);
}

test "SFU nonce safety: colliding SSRC from a second source never reuses a recipient nonce" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();

    const kV = mkKeys(11); // legitimate source of the SSRC
    const kW = mkKeys(12); // attacker, spoofs the same SSRC
    const kR = mkKeys(13); // recipient (the victim of any two-time-pad)
    const aV = mkAddr(21);
    const aW = mkAddr(22);
    const aR = mkAddr(23);
    try testing.expect(hub.noteEstablished(aV, kV));
    try testing.expect(hub.noteEstablished(aW, kW));
    try testing.expect(hub.noteEstablished(aR, kR));

    const ssrc: u32 = 0x5151_5151;
    const seq: u16 = 100;

    // V sends P1 at (ssrc, seq); it is forwarded (re-encrypted) to R.
    var v_buf: [64]u8 = undefined;
    const v_rtp = rtpPacket(seq, ssrc, "victim-P1", &v_buf);
    const v_in = srtp.deriveSessionKeys(kV.clientMaster(), kV.clientSalt());
    var v_wire_buf: [128]u8 = undefined;
    const v_wire = try srtp.protect(v_in, 0, v_rtp, &v_wire_buf);
    var v_plain: [128]u8 = undefined;
    const v_canon = hub.unprotectRtp(aV, v_wire, &v_plain) orelse return error.TestUnexpectedResult;
    var toR1_buf: [128]u8 = undefined;
    const toR1 = hub.protectRtp(aR, v_canon, &toR1_buf) orelse return error.TestUnexpectedResult;
    var toR1_copy: [128]u8 = undefined;
    @memcpy(toR1_copy[0..toR1.len], toR1);

    // W (authenticated) spoofs the SAME SSRC. It is REJECTED at ingress by the
    // ownership binding — V owns the SSRC.
    var w_buf: [64]u8 = undefined;
    const w_rtp = rtpPacket(seq, ssrc, "attack-P2", &w_buf);
    const w_in = srtp.deriveSessionKeys(kW.clientMaster(), kW.clientSalt());
    var w_wire_buf: [128]u8 = undefined;
    const w_wire = try srtp.protect(w_in, 0, w_rtp, &w_wire_buf);
    var w_plain: [128]u8 = undefined;
    try testing.expect(hub.unprotectRtp(aW, w_wire, &w_plain) == null);

    // Belt-and-suspenders: even if a different-plaintext frame reached the
    // outbound stage at the same (ssrc, seq), the per-recipient replay window
    // refuses to re-encrypt the already-used index (no two-time-pad).
    var attack_plain: [64]u8 = undefined;
    const attack_rtp = rtpPacket(seq, ssrc, "attack-P2", &attack_plain);
    var toR2_buf: [128]u8 = undefined;
    try testing.expect(hub.protectRtp(aR, attack_rtp, &toR2_buf) == null);

    // R still decrypts V's genuine P1 with R's server-write key.
    const r_out = srtp.deriveSessionKeys(kR.serverMaster(), kR.serverSalt());
    var r_rec: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, v_rtp, try srtp.unprotect(r_out, 0, toR1_copy[0..toR1.len], &r_rec));
}

test "SFU no cross-peer ROC poisoning: per-source inbound streams stay independent" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();

    const kV = mkKeys(31);
    const kW = mkKeys(32);
    const aV = mkAddr(24);
    const aW = mkAddr(25);
    try testing.expect(hub.noteEstablished(aV, kV));
    try testing.expect(hub.noteEstablished(aW, kW));

    // W drives ITS OWN (W, ssrc) stream to a high sequence.
    const w_ssrc: u32 = 0x9999_0000;
    const w_in = srtp.deriveSessionKeys(kW.clientMaster(), kW.clientSalt());
    var w_buf: [64]u8 = undefined;
    const w_rtp = rtpPacket(60000, w_ssrc, "w-data", &w_buf);
    var w_wire_buf: [128]u8 = undefined;
    const w_wire = try srtp.protect(w_in, 0, w_rtp, &w_wire_buf);
    var w_plain: [128]u8 = undefined;
    try testing.expect(hub.unprotectRtp(aW, w_wire, &w_plain) != null);

    // V uses a DIFFERENT ssrc at a LOW sequence. Because inbound state is keyed
    // per (source, ssrc), V's stream is fully independent of W's high sequence:
    // V decrypts correctly at ROC 0 (no cross-peer poisoning / blackhole).
    const v_ssrc: u32 = 0x9999_0001;
    const v_in = srtp.deriveSessionKeys(kV.clientMaster(), kV.clientSalt());
    var v_buf: [64]u8 = undefined;
    const v_rtp = rtpPacket(201, v_ssrc, "v-data", &v_buf);
    var v_wire_buf: [128]u8 = undefined;
    const v_wire = try srtp.protect(v_in, 0, v_rtp, &v_wire_buf);
    var v_plain: [128]u8 = undefined;
    const got = hub.unprotectRtp(aV, v_wire, &v_plain) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, v_rtp, got);
}

test "SFU lifecycle: re-handshake at same address re-keys; evict wipes; full table fails closed" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();

    const a1 = mkAddr(30);
    const k1 = mkKeys(1);
    const k2 = mkKeys(2);
    try testing.expect(hub.noteEstablished(a1, k1));
    // Re-handshake at the SAME address with NEW keys ⇒ context re-keyed.
    try testing.expect(hub.noteEstablished(a1, k2));

    const ssrc: u32 = 0x0BADF00D;
    const seq: u16 = 5;
    var rtp_buf: [64]u8 = undefined;
    const rtp = rtpPacket(seq, ssrc, "hello", &rtp_buf);
    // Egress now uses k2's server-write key.
    var enc_buf: [128]u8 = undefined;
    const wire = hub.protectRtp(a1, rtp, &enc_buf) orelse return error.TestUnexpectedResult;
    const k2_out = srtp.deriveSessionKeys(k2.serverMaster(), k2.serverSalt());
    var rec: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, rtp, try srtp.unprotect(k2_out, 0, wire, &rec));
    // k1's key can no longer open it.
    const k1_out = srtp.deriveSessionKeys(k1.serverMaster(), k1.serverSalt());
    try testing.expectError(error.AuthFailed, srtp.unprotect(k1_out, 0, wire, &rec));

    hub.evict(a1);
    try testing.expect(!hub.peerActive(a1));

    // Fill the table with live peers, then a new peer fails closed (never
    // recycles a live context).
    var i: usize = 0;
    while (i < max_peers) : (i += 1) {
        const ok = hub.noteEstablished(TransportAddress.fromBytes(&[_]u8{ 10, 0, @intCast(i >> 8), @intCast(i & 0xff) }, 6000) catch unreachable, mkKeys(@intCast(i & 0xff)));
        try testing.expect(ok);
    }
    try testing.expect(!hub.noteEstablished(mkAddr(200), mkKeys(7)));
}

test "SFU NACK-safety: the outbound replay window is keyed by the packet header, not a caller id" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();
    const kR = mkKeys(41);
    const aR = mkAddr(50);
    try testing.expect(hub.noteEstablished(aR, kR));

    const z: u32 = 0xABCD_EF01;
    const x: u32 = 0x1234_5678;

    // Forward header (ssrc=Z, seq=51, P1) to R → encrypted; R's Z-window uses 51.
    var p1_buf: [64]u8 = undefined;
    const p1 = rtpPacket(51, z, "P1", &p1_buf);
    var e1: [128]u8 = undefined;
    try testing.expect(hub.protectRtp(aR, p1, &e1) != null);

    // The exact NACK divergence: a DIFFERENT plaintext with the SAME header
    // (ssrc=Z, seq=51) — as a seq-keyed retransmit cache could hand back for a
    // NACK nominally about a different SSRC — is REFUSED (Z-window used 51). The
    // window follows the packet's OWN header, so it can never disagree with the
    // AES-CM nonce ⇒ no two-time-pad.
    var p2_buf: [64]u8 = undefined;
    const p2 = rtpPacket(51, z, "P2-different", &p2_buf);
    var e2: [128]u8 = undefined;
    try testing.expect(hub.protectRtp(aR, p2, &e2) == null);

    // A packet with a DIFFERENT header SSRC (X) at the same seq is an
    // independent SRTP stream to R ⇒ allowed.
    var px_buf: [64]u8 = undefined;
    const px = rtpPacket(51, x, "X-stream", &px_buf);
    var ex: [128]u8 = undefined;
    try testing.expect(hub.protectRtp(aR, px, &ex) != null);
}

test "SFU byte-identical intent: unknown (non-DTLS) address yields null crypto" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();
    const unknown = mkAddr(40);
    var out: [64]u8 = undefined;
    const zeros40: [40]u8 = @splat(0);
    const zeros12: [12]u8 = @splat(0);
    try testing.expect(hub.unprotectRtp(unknown, &zeros40, &out) == null);
    try testing.expect(hub.protectRtp(unknown, &zeros12, &out) == null);
    try testing.expect(hub.unprotectRtcp(unknown, &zeros40, &out) == null);
    try testing.expect(hub.protectRtcp(unknown, &zeros12, &out) == null);
}

fn sfuDtoOwnershipSweep(allocator: std.mem.Allocator) !void {
    var old = SfuSrtp.init(testing.allocator);
    defer old.wipe();
    try testing.expect(old.noteEstablished(mkAddr(1), mkKeys(1)));
    var packet: [64]u8 = undefined;
    var encrypted: [128]u8 = undefined;
    _ = old.protectRtp(mkAddr(1), rtpPacket(65535, 77, "retained", &packet), &encrypted) orelse return error.TestUnexpectedResult;
    const rtcp = [_]u8{ 0x80, 0xc8, 0, 1, 0, 0, 0, 77 };
    const keys = srtp.deriveSessionKeys(mkKeys(1).clientMaster(), mkKeys(1).clientSalt());
    var rtcp_wire_buf: [64]u8 = undefined;
    var rtcp_plain: [64]u8 = undefined;
    const rtcp_wire = try srtcp.protect(keys, 100, &rtcp, &rtcp_wire_buf);
    _ = old.unprotectRtcp(mkAddr(1), rtcp_wire, &rtcp_plain) orelse return error.TestUnexpectedResult;
    const old_ptr = old.peers.ptr;
    const old_peer = old.peers[0];
    const old_clock = old.clock;
    defer std.debug.assert(old.peers.ptr == old_ptr and std.meta.eql(old.peers[0], old_peer) and old.clock == old_clock);
    var snapshot = old.capture(allocator) catch |err| {
        var retry = try old.capture(testing.allocator);
        defer retry.deinit();
        return err;
    };
    defer snapshot.deinit();
    var restored = SfuSrtp.prepareRestore(allocator, &snapshot) catch |err| {
        var retry = try SfuSrtp.prepareRestore(testing.allocator, &snapshot);
        defer retry.wipe();
        try testing.expect(std.meta.eql(old_peer, retry.peers[0]));
        return err;
    };
    defer restored.wipe();
    try testing.expect(restored.peers.ptr != old.peers.ptr);
    try testing.expect(std.meta.eql(old_peer, restored.peers[0]));
    restored.evict(mkAddr(1));
    try testing.expect(old.peerActive(mkAddr(1)));
}

test "active media DTO SRTP owned capture restore all OOM boundaries preserve OLD and retry" {
    try testing.checkAllAllocationFailures(testing.allocator, sfuDtoOwnershipSweep, .{});
}

test "active media DTO SRTP actual packet rollover replay ownership and SRTCP exhaustion survive" {
    var old = SfuSrtp.init(testing.allocator);
    defer old.wipe();
    const source = mkAddr(1);
    const recipient = mkAddr(2);
    const source_keys = mkKeys(1);
    try testing.expect(old.noteEstablished(source, source_keys));
    try testing.expect(old.noteEstablished(recipient, mkKeys(2)));
    const inbound = srtp.deriveSessionKeys(source_keys.clientMaster(), source_keys.clientSalt());
    var packet_buf: [64]u8 = undefined;
    var protected_buf: [128]u8 = undefined;
    var plain_buf: [128]u8 = undefined;
    var outbound_buf: [128]u8 = undefined;
    const first = rtpPacket(65535, 77, "before-wrap", &packet_buf);
    const wire = try srtp.protect(inbound, 0, first, &protected_buf);
    const plain = old.unprotectRtp(source, wire, &plain_buf) orelse return error.TestUnexpectedResult;
    _ = old.protectRtp(recipient, plain, &outbound_buf) orelse return error.TestUnexpectedResult;
    const second = rtpPacket(0, 77, "after-wrap", &packet_buf);
    const wrapped_wire = try srtp.protect(inbound, 1, second, &protected_buf);
    const wrapped_plain = old.unprotectRtp(source, wrapped_wire, &plain_buf) orelse return error.TestUnexpectedResult;
    _ = old.protectRtp(recipient, wrapped_plain, &outbound_buf) orelse return error.TestUnexpectedResult;
    const rtcp = [_]u8{ 0x80, 0xc8, 0, 1, 0, 0, 0, 77 };
    old.findPeer(recipient).?.srtcp_out_index = std.math.maxInt(u31);
    _ = old.protectRtcp(recipient, &rtcp, &outbound_buf) orelse return error.TestUnexpectedResult;
    var snapshot = try old.capture(testing.allocator);
    defer snapshot.deinit();
    var restored = try SfuSrtp.prepareRestore(testing.allocator, &snapshot);
    defer restored.wipe();
    try testing.expectEqual(old.clock, restored.clock);
    try testing.expect(std.meta.eql(old.owners, restored.owners));
    try testing.expect(std.meta.eql(old.peers[0], restored.peers[0]));
    try testing.expect(std.meta.eql(old.peers[1], restored.peers[1]));
    try testing.expect(restored.unprotectRtp(source, wrapped_wire, &plain_buf) == null);
    try testing.expect(restored.protectRtp(recipient, second, &outbound_buf) == null);
    try testing.expect(restored.protectRtcp(recipient, &rtcp, &outbound_buf) == null);
    const third = rtpPacket(1, 77, "next-frame", &packet_buf);
    const next_wire = try srtp.protect(inbound, 1, third, &protected_buf);
    var old_plain: [128]u8 = undefined;
    var new_plain: [128]u8 = undefined;
    const a = old.unprotectRtp(source, next_wire, &old_plain) orelse return error.TestUnexpectedResult;
    const b = restored.unprotectRtp(source, next_wire, &new_plain) orelse return error.TestUnexpectedResult;
    var old_out: [128]u8 = undefined;
    var new_out: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, old.protectRtp(recipient, a, &old_out).?, restored.protectRtp(recipient, b, &new_out).?);
    try testing.expect(restored.unprotectRtp(source, next_wire, &new_plain) == null);
    try testing.expect(restored.noteEstablished(mkAddr(3), mkKeys(3)));
    var impostor: [128]u8 = undefined;
    const impostor_keys = srtp.deriveSessionKeys(mkKeys(3).clientMaster(), mkKeys(3).clientSalt());
    const forged_owner = try srtp.protect(impostor_keys, 0, third, &impostor);
    try testing.expect(restored.unprotectRtp(mkAddr(3), forged_owner, &new_plain) == null);
}

test "active media DTO SRTP malformed replay peer owner and material refuse before restore allocation" {
    var old = SfuSrtp.init(testing.allocator);
    defer old.wipe();
    try testing.expect(old.noteEstablished(mkAddr(1), mkKeys(1)));
    var snapshot = try old.capture(testing.allocator);
    defer snapshot.deinit();
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    snapshot.peers[0].srtcp_out_index = std.math.maxInt(u32);
    try testing.expectError(error.InvalidSnapshot, SfuSrtp.prepareRestore(failing.allocator(), &snapshot));
    snapshot.peers[0].srtcp_out_index = 0;
    snapshot.peers[0].out_streams[0] = .{ .active = true, .ssrc = 1, .seen = true, .replay_bits = 0 };
    try testing.expectError(error.InvalidSnapshot, SfuSrtp.prepareRestore(failing.allocator(), &snapshot));
    snapshot.peers[0].out_streams[0] = .{};
    snapshot.peers[1] = snapshot.peers[0];
    try testing.expectError(error.InvalidSnapshot, SfuSrtp.prepareRestore(failing.allocator(), &snapshot));
    snapshot.peers[1] = .{};
    snapshot.owners[0] = .{ .active = true, .addr = mkAddr(9), .ssrc = 1 };
    try testing.expectError(error.InvalidSnapshot, SfuSrtp.prepareRestore(failing.allocator(), &snapshot));
    snapshot.owners[0] = .{};
    try testing.expectEqual(@as(usize, 0), failing.alloc_index);
    old.peers[0].inbound.cipher[0] ^= 1;
    try testing.expectError(error.InvalidSnapshot, old.capture(testing.allocator));
    old.peers[0].inbound.cipher[0] ^= 1;
    var retry = try SfuSrtp.prepareRestore(testing.allocator, &snapshot);
    defer retry.wipe();
    try testing.expect(std.meta.eql(old.peers[0], retry.peers[0]));
}

test "active media DTO SRTCP authentic replay is refused and distinct SSRC index remains admissible" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();
    const peer = mkAddr(4);
    const material = mkKeys(4);
    try testing.expect(hub.noteEstablished(peer, material));
    const keys = srtp.deriveSessionKeys(material.clientMaster(), material.clientSalt());
    const first = [_]u8{ 0x80, 0xc8, 0, 1, 0, 0, 0, 11 };
    const distinct = [_]u8{ 0x80, 0xc8, 0, 1, 0, 0, 0, 12 };
    var first_buf: [64]u8 = undefined;
    var second_buf: [64]u8 = undefined;
    var plain: [64]u8 = undefined;
    const first_wire = try srtcp.protect(keys, 7, &first, &first_buf);
    const distinct_wire = try srtcp.protect(keys, 7, &distinct, &second_buf);
    try testing.expectEqualSlices(u8, &first, hub.unprotectRtcp(peer, first_wire, &plain).?);
    try testing.expectEqualSlices(u8, &distinct, hub.unprotectRtcp(peer, distinct_wire, &plain).?);
    try testing.expect(hub.unprotectRtcp(peer, first_wire, &plain) == null);
    try testing.expect(hub.unprotectRtcp(peer, distinct_wire, &plain) == null);
}

test "active media DTO SRTCP authentication capacity ownership reorder and 64 index boundary" {
    var old = SfuSrtp.init(testing.allocator);
    defer old.wipe();
    const peer = mkAddr(4);
    const material = mkKeys(4);
    try testing.expect(old.noteEstablished(peer, material));
    const keys = srtp.deriveSessionKeys(material.clientMaster(), material.clientSalt());
    const rtcp = [_]u8{ 0x80, 0xc8, 0, 1, 0, 0, 0, 11 };
    var wire_buf: [64]u8 = undefined;
    var plain: [64]u8 = undefined;
    var wire = try srtcp.protect(keys, 100, &rtcp, &wire_buf);
    try testing.expect(old.unprotectRtcp(peer, wire, &plain) != null);
    const before = old.peers[0];
    const before_owners = old.owners;
    const before_clock = old.clock;
    wire = try srtcp.protect(keys, std.math.maxInt(u31), &rtcp, &wire_buf);
    wire_buf[wire.len - 1] ^= 1;
    try testing.expect(old.unprotectRtcp(peer, wire, &plain) == null);
    try testing.expect(std.meta.eql(before, old.peers[0]));
    wire_buf[wire.len - 1] ^= 1;
    try testing.expect(old.unprotectRtcp(peer, wire, plain[0..7]) == null);
    try testing.expect(std.meta.eql(before, old.peers[0]));
    try testing.expect(std.meta.eql(before_owners, old.owners));
    try testing.expectEqual(before_clock, old.clock);
    wire = try srtcp.protect(keys, 37, &rtcp, &wire_buf); // distance 63
    try testing.expect(old.unprotectRtcp(peer, wire, &plain) != null);
    try testing.expect(old.unprotectRtcp(peer, wire, &plain) == null);
    wire = try srtcp.protect(keys, 36, &rtcp, &wire_buf); // distance 64
    try testing.expect(old.unprotectRtcp(peer, wire, &plain) == null);
    try testing.expect(old.noteEstablished(mkAddr(5), mkKeys(5)));
    const other_keys = srtp.deriveSessionKeys(mkKeys(5).clientMaster(), mkKeys(5).clientSalt());
    wire = try srtcp.protect(other_keys, 1, &rtcp, &wire_buf);
    const other_before = old.peers[1];
    try testing.expect(old.unprotectRtcp(mkAddr(5), wire, &plain) == null);
    try testing.expect(std.meta.eql(other_before, old.peers[1]));
    var snapshot = try old.capture(testing.allocator);
    defer snapshot.deinit();
    var restored = try SfuSrtp.prepareRestore(testing.allocator, &snapshot);
    defer restored.wipe();
    wire = try srtcp.protect(keys, 37, &rtcp, &wire_buf);
    try testing.expect(restored.unprotectRtcp(peer, wire, &plain) == null);
    wire = try srtcp.protect(keys, 99, &rtcp, &wire_buf);
    try testing.expect(restored.unprotectRtcp(peer, wire, &plain) != null);
    try testing.expect(restored.unprotectRtcp(peer, wire, &plain) == null);
    wire = try srtcp.protect(keys, 164, &rtcp, &wire_buf);
    try testing.expect(restored.unprotectRtcp(peer, wire, &plain) != null);
    wire = try srtcp.protect(keys, 100, &rtcp, &wire_buf);
    try testing.expect(restored.unprotectRtcp(peer, wire, &plain) == null);
}

test "active media DTO SRTCP full per SSRC table never evicts retained replay authority" {
    var old = SfuSrtp.init(testing.allocator);
    defer old.wipe();
    const peer = mkAddr(4);
    const material = mkKeys(4);
    try testing.expect(old.noteEstablished(peer, material));
    const keys = srtp.deriveSessionKeys(material.clientMaster(), material.clientSalt());
    var rtcp = [_]u8{ 0x80, 0xc8, 0, 1, 0, 0, 0, 0 };
    var wire_buf: [64]u8 = undefined;
    var plain: [64]u8 = undefined;
    for (0..max_srtcp_in_streams) |i| {
        std.mem.writeInt(u32, rtcp[4..8], @intCast(i + 1), .big);
        const wire = try srtcp.protect(keys, 0, &rtcp, &wire_buf);
        try testing.expect(old.unprotectRtcp(peer, wire, &plain) != null);
    }
    const before = old.peers[0];
    const clock = old.clock;
    const owners = old.owners;
    std.mem.writeInt(u32, rtcp[4..8], max_srtcp_in_streams + 1, .big);
    const excess = try srtcp.protect(keys, 0, &rtcp, &wire_buf);
    try testing.expect(old.unprotectRtcp(peer, excess, &plain) == null);
    try testing.expect(std.meta.eql(before, old.peers[0]));
    try testing.expect(std.meta.eql(owners, old.owners));
    try testing.expectEqual(clock, old.clock);
    var snapshot = try old.capture(testing.allocator);
    defer snapshot.deinit();
    snapshot.peers[0].srtcp_in[0].bits = 2;
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.InvalidSnapshot, SfuSrtp.prepareRestore(failing.allocator(), &snapshot));
    try testing.expectEqual(@as(usize, 0), failing.alloc_index);
    snapshot.peers[0].srtcp_in[0].bits = 1;
    var restored = try SfuSrtp.prepareRestore(testing.allocator, &snapshot);
    defer restored.wipe();
    try testing.expect(restored.unprotectRtcp(peer, excess, &plain) == null);
    for (0..max_srtcp_in_streams) |i| {
        std.mem.writeInt(u32, rtcp[4..8], @intCast(i + 1), .big);
        const wire = try srtcp.protect(keys, 0, &rtcp, &wire_buf);
        try testing.expect(restored.unprotectRtcp(peer, wire, &plain) == null);
    }
}

test "active media DTO SRTCP same key reinstall preserves replay and genuinely changed key retires it" {
    var old = SfuSrtp.init(testing.allocator);
    defer old.wipe();
    const peer = mkAddr(4);
    const material = mkKeys(4);
    try testing.expect(old.noteEstablished(peer, material));
    const keys = srtp.deriveSessionKeys(material.clientMaster(), material.clientSalt());
    const rtcp = [_]u8{ 0x80, 0xc8, 0, 1, 0, 0, 0, 11 };
    var wire_buf: [64]u8 = undefined;
    var plain: [64]u8 = undefined;
    const wire = try srtcp.protect(keys, 7, &rtcp, &wire_buf);
    try testing.expect(old.unprotectRtcp(peer, wire, &plain) != null);
    const replay = old.peers[0].srtcp_in;
    try testing.expect(old.noteEstablished(peer, material));
    try testing.expect(std.meta.eql(replay, old.peers[0].srtcp_in));
    try testing.expect(old.unprotectRtcp(peer, wire, &plain) == null);
    const replacement = mkKeys(5);
    try testing.expect(old.noteEstablished(peer, replacement));
    try testing.expect(old.unprotectRtcp(peer, wire, &plain) == null); // old auth key denied
    const new_keys = srtp.deriveSessionKeys(replacement.clientMaster(), replacement.clientSalt());
    const new_wire = try srtcp.protect(new_keys, 7, &rtcp, &wire_buf);
    try testing.expect(old.unprotectRtcp(peer, new_wire, &plain) != null);
    try testing.expect(old.unprotectRtcp(peer, new_wire, &plain) == null);
}

test "active media eviction causal authenticated RTP ninth stream never forgets first replay" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();
    const addr = mkAddr(20);
    const material = mkKeys(41);
    try testing.expect(hub.noteEstablished(addr, material));
    const ingress = srtp.deriveSessionKeys(material.clientMaster(), material.clientSalt());
    var plain_buf: [64]u8 = undefined;
    var wire_buf: [128]u8 = undefined;
    var output: [128]u8 = undefined;
    var first: [128]u8 = undefined;
    var first_len: usize = 0;
    for (0..9) |i| {
        const packet = rtpPacket(1, @intCast(1000 + i), "accepted real media", &plain_buf);
        const wire = try srtp.protect(ingress, 0, packet, &wire_buf);
        if (i == 0) {
            first_len = wire.len;
            @memcpy(first[0..first_len], wire);
        }
        try testing.expect(hub.unprotectRtp(addr, wire, &output) != null);
    }
    // Same peer/key, byte-identical authenticated packet already accepted.
    try testing.expect(hub.unprotectRtp(addr, first[0..first_len], &output) == null);
}

test "active media eviction causal authenticated owner capacity never opens foreign SSRC" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();
    const a = mkAddr(21);
    const b = mkAddr(22);
    const ka = mkKeys(42);
    const kb = mkKeys(43);
    try testing.expect(hub.noteEstablished(a, ka));
    try testing.expect(hub.noteEstablished(b, kb));
    const ingress_a = srtp.deriveSessionKeys(ka.clientMaster(), ka.clientSalt());
    const ingress_b = srtp.deriveSessionKeys(kb.clientMaster(), kb.clientSalt());
    var packet_buf: [64]u8 = undefined;
    var wire_buf: [128]u8 = undefined;
    var output: [128]u8 = undefined;
    const first = try srtp.protect(ingress_a, 0, rtpPacket(1, 2000, "A owns this source", &packet_buf), &wire_buf);
    try testing.expect(hub.unprotectRtp(a, first, &output) != null);
    var spoof: [128]u8 = undefined;
    const foreign = try srtp.protect(ingress_b, 0, rtpPacket(1, 2000, "B signed foreign source", &packet_buf), &spoof);
    try testing.expect(hub.unprotectRtp(b, foreign, &output) == null);
    for (1..max_owners) |i| {
        const wire = try srtp.protect(ingress_a, 0, rtpPacket(1, @intCast(2000 + i), "A another source", &packet_buf), &wire_buf);
        try testing.expect(hub.unprotectRtp(a, wire, &output) != null);
    }
    var before = try hub.capture(testing.allocator);
    defer before.deinit();
    const overflow = try srtp.protect(ingress_a, 0, rtpPacket(1, 2000 + max_owners, "cannot recycle live source", &packet_buf), &wire_buf);
    try testing.expect(hub.unprotectRtp(a, overflow, &output) == null);
    // Authenticated by B's own key but still the SSRC previously owned by A.
    try testing.expect(hub.unprotectRtp(b, foreign, &output) == null);
    var after = try hub.capture(testing.allocator);
    defer after.deinit();
    try testing.expectEqualDeep(before.peers, after.peers);
    try testing.expectEqualDeep(before.owners, after.owners);
    try testing.expectEqual(before.clock, after.clock);
    var overflow_copy: [128]u8 = undefined;
    @memcpy(overflow_copy[0..overflow.len], overflow);
    const overflow_len = overflow.len;
    const known = try srtp.protect(ingress_a, 0, rtpPacket(2, 2000, "known source continues", &packet_buf), &wire_buf);
    try testing.expect(hub.unprotectRtp(a, known, &output) != null);
    var candidate = try SfuSrtp.prepareRestore(testing.allocator, &before);
    defer candidate.wipe();
    try testing.expect(candidate.unprotectRtp(a, overflow_copy[0..overflow_len], &output) == null);
    try testing.expect(candidate.unprotectRtp(b, foreign, &output) == null);
}

test "active media DTO RTP ingress refusals do not allocate or advance accepted state" {
    var hub = SfuSrtp.init(testing.allocator);
    defer hub.wipe();
    const addr = mkAddr(23);
    const material = mkKeys(44);
    try testing.expect(hub.noteEstablished(addr, material));
    const ingress = srtp.deriveSessionKeys(material.clientMaster(), material.clientSalt());
    var packet_buf: [64]u8 = undefined;
    var wire_buf: [128]u8 = undefined;
    var output: [128]u8 = undefined;
    const packet = rtpPacket(100, 3000, "authenticated source", &packet_buf);
    const wire = try srtp.protect(ingress, 0, packet, &wire_buf);
    var before = try hub.capture(testing.allocator);
    defer before.deinit();
    var bad: [128]u8 = undefined;
    @memcpy(bad[0..wire.len], wire);
    bad[wire.len - 1] ^= 1;
    try testing.expect(hub.unprotectRtp(addr, bad[0..wire.len], &output) == null);
    try testing.expect(hub.unprotectRtp(addr, wire, output[0..1]) == null);
    var after = try hub.capture(testing.allocator);
    defer after.deinit();
    try testing.expectEqualDeep(before.peers, after.peers);
    try testing.expectEqualDeep(before.owners, after.owners);
    try testing.expectEqual(before.clock, after.clock);
    try testing.expect(hub.unprotectRtp(addr, wire, &output) != null);
    var accepted = try hub.capture(testing.allocator);
    defer accepted.deinit();
    try testing.expect(hub.unprotectRtp(addr, wire, &output) == null);
    var replayed = try hub.capture(testing.allocator);
    defer replayed.deinit();
    try testing.expectEqualDeep(accepted.peers, replayed.peers);
    try testing.expectEqualDeep(accepted.owners, replayed.owners);
    try testing.expectEqual(accepted.clock, replayed.clock);
}

const SfuJoinTamper = enum { missing_owner, foreign_owner, missing_ingress };

// The source proof comes from an actual authenticated ingress packet. A second
// installed peer is deliberately present so the malformed restored graph can
// demonstrate an authority change, rather than merely a structural difference.
fn sfuJoinCausal(comptime rtcp: bool, comptime tamper: SfuJoinTamper) !void {
    var old = SfuSrtp.init(testing.allocator);
    defer old.wipe();
    const a = mkAddr(1);
    const b = mkAddr(2);
    const ka = mkKeys(1);
    const kb = mkKeys(2);
    try testing.expect(old.noteEstablished(a, ka));
    try testing.expect(old.noteEstablished(b, kb));
    const ssrc: u32 = 991;
    var packet: [64]u8 = undefined;
    var wire: [128]u8 = undefined;
    var output: [128]u8 = undefined;
    const canonical = if (rtcp) blk: {
        var report: [28]u8 = @splat(0);
        report[0] = 0x80;
        report[1] = 0xc8;
        std.mem.writeInt(u16, report[2..4], 6, .big);
        std.mem.writeInt(u32, report[4..8], ssrc, .big);
        @memcpy(packet[0..report.len], &report);
        break :blk packet[0..report.len];
    } else rtpPacket(1, ssrc, "accepted", &packet);
    const akeys = srtp.deriveSessionKeys(ka.clientMaster(), ka.clientSalt());
    const accepted = if (rtcp) try srtcp.protect(akeys, 1, canonical, &wire) else try srtp.protect(akeys, 0, canonical, &wire);
    const recovered = if (rtcp) old.unprotectRtcp(a, accepted, &output) else old.unprotectRtp(a, accepted, &output);
    try testing.expectEqualSlices(u8, canonical, recovered orelse return error.TestUnexpectedResult);
    const bkeys = srtp.deriveSessionKeys(kb.clientMaster(), kb.clientSalt());
    var foreign_wire: [128]u8 = undefined;
    const foreign = if (rtcp) try srtcp.protect(bkeys, 2, canonical, &foreign_wire) else try srtp.protect(bkeys, 0, canonical, &foreign_wire);
    try testing.expect((if (rtcp) old.unprotectRtcp(b, foreign, &output) else old.unprotectRtp(b, foreign, &output)) == null);
    var carry = try old.capture(testing.allocator);
    defer carry.deinit();
    var owner_index: ?usize = null;
    for (carry.owners, 0..) |owner, i| if (owner.active and owner.ssrc == ssrc) {
        try testing.expect(owner.addr.eql(a));
        owner_index = i;
        break;
    };
    const index = owner_index orelse return error.TestUnexpectedResult;
    switch (tamper) {
        .missing_owner => carry.owners[index] = .{},
        .foreign_owner => carry.owners[index].addr = b,
        .missing_ingress => for (carry.peers) |*peer| {
            if (!peer.active or !peer.addr.eql(a)) continue;
            if (rtcp) {
                for (&peer.srtcp_in) |*context| if (context.active and context.ssrc == ssrc) {
                    context.* = .{};
                };
            } else {
                for (&peer.in_streams) |*stream| if (stream.active and stream.ssrc == ssrc) {
                    stream.* = .{};
                };
            }
        },
    }
    // On the unfixed source these are genuine restored candidates. Their
    // cleanup is explicit even when the final refusal oracle fails.
    var restored = SfuSrtp.prepareRestore(testing.allocator, &carry) catch |err| {
        try testing.expectEqual(error.InvalidSnapshot, err);
        return;
    };
    defer restored.wipe();
    if (tamper != .missing_ingress) {
        const changed = if (rtcp) restored.unprotectRtcp(b, foreign, &output) else restored.unprotectRtp(b, foreign, &output);
        try testing.expectEqualSlices(u8, canonical, changed orelse return error.TestUnexpectedResult);
        std.debug.print("Sfu join causal: authenticated {s} OLD owner retained, malformed restored owner grants foreign peer\n", .{if (rtcp) "SRTCP" else "RTP"});
    }
    try testing.expectError(error.InvalidSnapshot, carry.validate());
}

test "active media ownership join causal accepted RTP cannot lose owner" {
    try sfuJoinCausal(false, .missing_owner);
}
test "active media ownership join causal accepted SRTCP cannot lose owner" {
    try sfuJoinCausal(true, .missing_owner);
}
test "active media ownership join causal accepted RTP cannot retarget owner" {
    try sfuJoinCausal(false, .foreign_owner);
}
test "active media ownership join causal accepted SRTCP cannot retarget owner" {
    try sfuJoinCausal(true, .foreign_owner);
}
test "active media ownership join causal RTP owner cannot lose accepted history" {
    try sfuJoinCausal(false, .missing_ingress);
}
test "active media ownership join causal SRTCP owner cannot lose accepted history" {
    try sfuJoinCausal(true, .missing_ingress);
}

const SfuJoinHistory = enum { rtp_only, srtcp_only, mixed, outbound_only, idle };

fn sfuValidJoinHistory(mode: SfuJoinHistory) !void {
    var old = SfuSrtp.init(testing.allocator);
    defer old.wipe();
    const a = mkAddr(1);
    const b = mkAddr(2);
    const material = mkKeys(1);
    try testing.expect(old.noteEstablished(a, material));
    try testing.expect(old.noteEstablished(b, mkKeys(2)));
    const keys = srtp.deriveSessionKeys(material.clientMaster(), material.clientSalt());
    var packet: [64]u8 = undefined;
    var wire: [128]u8 = undefined;
    var output: [128]u8 = undefined;
    if (mode == .rtp_only or mode == .mixed) {
        const canonical = rtpPacket(1, 991, "owned", &packet);
        const protected = try srtp.protect(keys, 0, canonical, &wire);
        try testing.expectEqualSlices(u8, canonical, old.unprotectRtp(a, protected, &output).?);
        // Its foreign recipient retains outbound nonce history, not SSRC
        // ownership. The strict snapshot must accept this genuine direction.
        try testing.expect(old.protectRtp(b, canonical, &output) != null);
    }
    if (mode == .srtcp_only or mode == .mixed) {
        var report: [28]u8 = @splat(0);
        report[0] = 0x80;
        report[1] = 200;
        std.mem.writeInt(u16, report[2..4], 6, .big);
        std.mem.writeInt(u32, report[4..8], 991, .big);
        const protected = try srtcp.protect(keys, 1, &report, &wire);
        try testing.expectEqualSlices(u8, &report, old.unprotectRtcp(a, protected, &output).?);
    }
    if (mode == .outbound_only) {
        const canonical = rtpPacket(1, 992, "native-source", &packet);
        try testing.expect(old.protectRtp(b, canonical, &output) != null);
        for (old.owners) |owner| try testing.expect(!owner.active);
    }
    var carry = try old.capture(testing.allocator);
    defer carry.deinit();
    try carry.validate();
    var candidate = try SfuSrtp.prepareRestore(testing.allocator, &carry);
    defer candidate.wipe();
    var again = try candidate.capture(testing.allocator);
    defer again.deinit();
    try testing.expectEqual(carry.clock, again.clock);
    try testing.expect(std.meta.eql(carry.owners, again.owners));
    for (carry.peers, again.peers) |first, second| try testing.expect(std.meta.eql(first, second));
}

test "active media ownership join legal RTP SRTCP mixed outbound-only and idle preserve exact state" {
    inline for (std.meta.tags(SfuJoinHistory)) |mode| try sfuValidJoinHistory(mode);
}

test "active media ownership join malformed joins refuse before allocation preserve OLD and retry" {
    var old = SfuSrtp.init(testing.allocator);
    defer old.wipe();
    const a = mkAddr(1);
    const b = mkAddr(2);
    const material = mkKeys(1);
    try testing.expect(old.noteEstablished(a, material));
    try testing.expect(old.noteEstablished(b, mkKeys(2)));
    const keys = srtp.deriveSessionKeys(material.clientMaster(), material.clientSalt());
    var packet: [64]u8 = undefined;
    var wire: [128]u8 = undefined;
    var output: [128]u8 = undefined;
    const canonical = rtpPacket(1, 991, "retained", &packet);
    const protected = try srtp.protect(keys, 0, canonical, &wire);
    try testing.expect(old.unprotectRtp(a, protected, &output) != null);
    var carry = try old.capture(testing.allocator);
    defer carry.deinit();
    const original_owners = carry.owners;
    var owner_index: ?usize = null;
    for (carry.owners, 0..) |owner, i| if (owner.active and owner.ssrc == 991) {
        owner_index = i;
        break;
    };
    const index = owner_index orelse return error.TestUnexpectedResult;
    inline for (.{ SfuJoinTamper.missing_owner, SfuJoinTamper.foreign_owner }) |tamper| {
        carry.owners = original_owners;
        if (tamper == .missing_owner) carry.owners[index] = .{} else carry.owners[index].addr = b;
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
        try testing.expectError(error.InvalidSnapshot, SfuSrtp.prepareRestore(failing.allocator(), &carry));
        try testing.expectEqual(@as(usize, 0), failing.alloc_index);
        // A refused untrusted restoration never weakens the accepted source.
        try testing.expect(old.unprotectRtp(a, protected, &output) == null);
        var observed = try old.capture(testing.allocator);
        defer observed.deinit();
        try testing.expect(std.meta.eql(original_owners, observed.owners));
        try testing.expectEqual(carry.clock, observed.clock);
        for (carry.peers, observed.peers) |first, second| try testing.expect(std.meta.eql(first, second));
    }
    carry.owners = original_owners;
    var peer_index: ?usize = null;
    for (carry.peers, 0..) |peer, i| if (peer.active and peer.addr.eql(a)) {
        peer_index = i;
        break;
    };
    const pi = peer_index orelse return error.TestUnexpectedResult;
    var stream_index: ?usize = null;
    for (carry.peers[pi].in_streams, 0..) |stream, i| if (stream.active and stream.seen and stream.ssrc == 991) {
        stream_index = i;
        break;
    };
    const si = stream_index orelse return error.TestUnexpectedResult;
    const original_stream = carry.peers[pi].in_streams[si];
    carry.peers[pi].in_streams[si] = .{};
    var failing_orphan = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.InvalidSnapshot, SfuSrtp.prepareRestore(failing_orphan.allocator(), &carry));
    try testing.expectEqual(@as(usize, 0), failing_orphan.alloc_index);
    carry.peers[pi].in_streams[si] = original_stream;
    var retry = try SfuSrtp.prepareRestore(testing.allocator, &carry);
    defer retry.wipe();
    try testing.expect(retry.unprotectRtp(a, protected, &output) == null);
    var foreign: [128]u8 = undefined;
    const foreign_keys = srtp.deriveSessionKeys(mkKeys(2).clientMaster(), mkKeys(2).clientSalt());
    const forged = try srtp.protect(foreign_keys, 0, canonical, &foreign);
    try testing.expect(retry.unprotectRtp(b, forged, &output) == null);
}

test "physical media SFU tentative authentic ingress abort preserves replay owner clock and identical retry" {
    var source = SfuSrtp.init(testing.allocator);
    defer source.wipe();
    const address = mkAddr(1);
    const material = mkKeys(1);
    try testing.expect(source.noteEstablished(address, material));
    const old_peer = source.peers[0];
    const old_owners = source.owners;
    const old_clock = source.clock;
    var canonical_storage: [128]u8 = undefined;
    const canonical = rtpPacket(65535, 101, "tentative-authentic", &canonical_storage);
    const client = srtp.deriveSessionKeys(material.clientMaster(), material.clientSalt());
    var wire_storage: [256]u8 = undefined;
    const wire = try srtp.protect(client, 0, canonical, &wire_storage);
    var plain: [256]u8 = undefined;
    const tentative = source.prepareIngressRtp(address, wire, &plain) orelse return error.TestUnexpectedResult;
    var held = true;
    defer if (held) source.abortIngress(tentative.receipt) catch unreachable;
    try testing.expectEqualDeep(old_peer, source.peers[0]);
    try testing.expectEqualDeep(old_owners, source.owners);
    try testing.expectEqual(old_clock, source.clock);
    try testing.expectEqualSlices(u8, canonical, tentative.plain);
    var fail = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.Busy, source.capture(fail.allocator()));
    try testing.expectEqual(@as(usize, 0), fail.alloc_index);
    try testing.expect(!source.noteEstablished(address, material));
    try source.abortIngress(tentative.receipt);
    held = false;
    try testing.expectEqualDeep(old_peer, source.peers[0]);
    try testing.expectEqualDeep(old_owners, source.owners);
    try testing.expectEqual(old_clock, source.clock);
    const retry = source.prepareIngressRtp(address, wire, &plain) orelse return error.TestUnexpectedResult;
    defer if (source.pending_ingress != null) source.abortIngress(retry.receipt) catch unreachable;
    try testing.expectError(error.StaleIngress, source.abortIngress(tentative.receipt));
    try source.validateIngress(retry.receipt);
    source.commitIngress(retry.receipt);
    try testing.expect(source.unprotectRtp(address, wire, &plain) == null);
    var next_storage: [128]u8 = undefined;
    const next = rtpPacket(0, 101, "next-rollover", &next_storage);
    var next_wire_storage: [256]u8 = undefined;
    const next_wire = try srtp.protect(client, 1, next, &next_wire_storage);
    try testing.expectEqualSlices(u8, next, source.unprotectRtp(address, next_wire, &plain).?);
}
test "physical media SFU tentative canonical mutation foreign source and same-address reuse cannot publish" {
    var source = SfuSrtp.init(testing.allocator);
    defer source.wipe();
    const address = mkAddr(1);
    const material = mkKeys(1);
    try testing.expect(source.noteEstablished(address, material));
    var canonical_storage: [128]u8 = undefined;
    const canonical = rtpPacket(7, 103, "byte-bound", &canonical_storage);
    const client = srtp.deriveSessionKeys(material.clientMaster(), material.clientSalt());
    var wire_storage: [256]u8 = undefined;
    const wire = try srtp.protect(client, 0, canonical, &wire_storage);
    var plain: [256]u8 = undefined;
    const original = source.prepareIngressRtp(address, wire, &plain) orelse return error.TestUnexpectedResult;
    defer if (source.pending_ingress != null) source.abortIngress(source.pending_ingress.?.receipt) catch unreachable;
    plain[12] ^= 1;
    try testing.expectError(error.StaleIngress, source.validateIngress(original.receipt));
    try source.abortIngress(original.receipt);
    source.wipe();
    source = SfuSrtp.init(testing.allocator); // actual same source address, NEW lifetime
    try testing.expect(source.noteEstablished(address, material));
    const current = source.prepareIngressRtp(address, wire, &plain) orelse return error.TestUnexpectedResult;
    try testing.expect(current.receipt != original.receipt);
    try testing.expectError(error.StaleIngress, source.abortIngress(original.receipt));
    var foreign = SfuSrtp.init(testing.allocator);
    defer foreign.wipe();
    try testing.expect(foreign.noteEstablished(address, material));
    var other_plain: [256]u8 = undefined;
    const other = foreign.prepareIngressRtp(address, wire, &other_plain) orelse return error.TestUnexpectedResult;
    defer if (foreign.pending_ingress != null) foreign.abortIngress(other.receipt) catch unreachable;
    try testing.expectError(error.StaleIngress, foreign.validateIngress(current.receipt));
    try testing.expectError(error.StaleIngress, source.abortIngress(other.receipt));
    try foreign.validateIngress(other.receipt);
    foreign.commitIngress(other.receipt);
    try source.validateIngress(current.receipt);
    source.commitIngress(current.receipt);
}
test "physical media SFU tentative SRTCP abort leaves authentic per-SSRC replay unconsumed" {
    var source = SfuSrtp.init(testing.allocator);
    defer source.wipe();
    const address = mkAddr(1);
    const material = mkKeys(1);
    try testing.expect(source.noteEstablished(address, material));
    const old_peer = source.peers[0];
    const old_clock = source.clock;
    var report: [28]u8 = @splat(0);
    report[0] = 0x80;
    report[1] = 200;
    std.mem.writeInt(u16, report[2..4], 6, .big);
    std.mem.writeInt(u32, report[4..8], 107, .big);
    var wire_storage: [128]u8 = undefined;
    const client = srtp.deriveSessionKeys(material.clientMaster(), material.clientSalt());
    const wire = try srtcp.protect(client, 64, &report, &wire_storage);
    var plain: [128]u8 = undefined;
    const tentative = source.prepareIngressRtcp(address, wire, &plain) orelse return error.TestUnexpectedResult;
    defer if (source.pending_ingress != null) source.abortIngress(source.pending_ingress.?.receipt) catch unreachable;
    try testing.expectEqualDeep(old_peer, source.peers[0]);
    try testing.expectEqual(old_clock, source.clock);
    try source.abortIngress(tentative.receipt);
    try testing.expectEqualSlices(u8, &report, source.unprotectRtcp(address, wire, &plain).?);
    try testing.expect(source.unprotectRtcp(address, wire, &plain) == null);
}

test "physical media SFU last issued ingress completes without new serial and exhausted admission leaves accepted authority" {
    var source = SfuSrtp.init(testing.allocator);
    defer source.wipe();
    const address = mkAddr(1);
    const material = mkKeys(1);
    try testing.expect(source.noteEstablished(address, material));
    source.next_ingress = std.math.maxInt(u64) - 1;
    var canonical_storage: [128]u8 = undefined;
    const canonical = rtpPacket(31, 105, "last-source-issuance", &canonical_storage);
    var wire_storage: [256]u8 = undefined;
    const client = srtp.deriveSessionKeys(material.clientMaster(), material.clientSalt());
    const wire = try srtp.protect(client, 0, canonical, &wire_storage);
    var plain: [256]u8 = undefined;
    const issued = source.prepareIngressRtp(address, wire, &plain) orelse return error.TestUnexpectedResult;
    defer if (source.pending_ingress != null) source.abortIngress(issued.receipt) catch unreachable;
    try testing.expectEqual(std.math.maxInt(u64), source.next_ingress);
    try source.validateIngress(issued.receipt);
    source.commitIngress(issued.receipt);
    const original_peer = source.peers[0];
    const original_owners = source.owners;
    const original_clock = source.clock;
    const next_canonical = rtpPacket(32, 105, "refused-exhausted-source", &canonical_storage);
    const next_wire = try srtp.protect(client, 0, next_canonical, &wire_storage);
    try testing.expect(source.prepareIngressRtp(address, next_wire, &plain) == null);
    try testing.expectEqualDeep(original_peer, source.peers[0]);
    try testing.expectEqualDeep(original_owners, source.owners);
    try testing.expectEqual(original_clock, source.clock);
    try testing.expect(source.pending_ingress == null);
}
