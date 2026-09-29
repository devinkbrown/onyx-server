// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SFU media-transport control plane: the per-call registry that ties each
//! call participant to its ICE credentials and (once a connectivity check
//! succeeds) its bound remote UDP media address, and computes the RTP forward
//! set for the selective-forwarding unit.
//!
//! This is the transport plane's control core — pure and socket-free, so it is
//! fully testable on its own. The live UDP socket (a later layer) drives it:
//! it allocates an endpoint per `MEDIA OFFER`, looks endpoints up by ICE ufrag
//! when a STUN binding arrives, binds the peer address on a successful check,
//! and asks `forwardTargets` where to relay each inbound RTP packet.
//!
//! Credentials follow ICE (RFC 8445 §5.3): a ufrag/pwd pair the server offers
//! per participant. The inbound STUN USERNAME is `<server-ufrag>:<peer-ufrag>`,
//! so a binding is demultiplexed back to a participant by its server ufrag.
const std = @import("std");
const ice = @import("../proto/ice.zig");
const stun = @import("../proto/stun.zig");
const srtp = @import("../proto/srtp.zig");
const rtp_nack = @import("rtp_nack.zig");
const rtp_ext = @import("../proto/rtp_ext.zig");

/// Packets retained per sender for NACK retransmission (RFC 4585).
/// This cache is the product recovery path: at most `rtx_capacity` packets
/// per publisher, oldest sequence dropped first. A distinct RFC 4588 RTX
/// SSRC is not the product; DTLS-SRTP cannot re-protect an index already
/// sent to that recipient without reusing the SRTP nonce.
pub const rtx_capacity: usize = 512;

/// SRTP master key (16) + master salt (14): the per-call SDES keying material
/// the server distributes to every participant over the signaling channel.
pub const group_key_len: usize = srtp.master_key_len + srtp.master_salt_len;

pub const ufrag_len: usize = 8;
pub const pwd_len: usize = 24;
/// Max SFU forward fan-out considered per inbound packet (call size cap).
pub const max_forward: usize = 64;

pub const TransportAddress = ice.TransportAddress;

/// One participant's media-transport state within a call.
pub const Endpoint = struct {
    /// ICE credentials the server offers this participant (RFC 8445 §5.3).
    ufrag: [ufrag_len]u8,
    pwd: [pwd_len]u8,
    /// The peer's bound media address, set once a connectivity check succeeds.
    /// Null means ICE has not completed; the SFU skips it as a forward target.
    remote: ?TransportAddress = null,
    /// Highest spatial layer forwarded to this receiver. 255 accepts every
    /// layer. Another receiver's ceiling is a different endpoint field.
    max_spatial: u8 = 255,
    /// The RTP SSRC the participant publishes (learned from its first packet).
    ssrc: u32 = 0,
    /// Media packets/bytes received from this participant and relayed onward.
    rx_packets: u64 = 0,
    rx_bytes: u64 = 0,
    /// Recently-relayed RTP for this sender, for NACK retransmission.
    rtx: rtp_nack.RetransmitBuffer,

    pub fn ufragSlice(self: *const Endpoint) []const u8 {
        return self.ufrag[0..];
    }
    pub fn pwdSlice(self: *const Endpoint) []const u8 {
        return self.pwd[0..];
    }
    pub fn connected(self: *const Endpoint) bool {
        return self.remote != null;
    }
};

const ufrag_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Canonical 18-byte key for an address index: ip(16) ++ port(2, big-endian).
/// The IP is always 16 fully-initialized bytes (IPv4 lives in the first 4),
/// so byte-array hashing is well-defined.
const AddrKey = [18]u8;
const UfragKey = [ufrag_len]u8;

fn addrKey(a: TransportAddress) AddrKey {
    var k: AddrKey = undefined;
    @memcpy(k[0..16], &a.ip);
    std.mem.writeInt(u16, k[16..18], a.port, .big);
    return k;
}

fn ufragKey(ufrag: []const u8) ?UfragKey {
    if (ufrag.len != ufrag_len) return null;
    var key: UfragKey = undefined;
    @memcpy(key[0..], ufrag);
    return key;
}

pub const MediaTransport = struct {
    allocator: std.mem.Allocator,
    /// Composite "channel\x00participant" -> Endpoint.
    endpoints: std.StringHashMapUnmanaged(Endpoint) = .empty,
    /// Server ufrag -> composite key, for STUN binding demultiplexing.
    by_ufrag: std.AutoHashMapUnmanaged(UfragKey, []const u8) = .empty,
    /// Bound peer address -> composite key, for routing inbound RTP by source.
    by_addr: std.AutoHashMapUnmanaged(AddrKey, []const u8) = .empty,
    /// Learned RTP SSRC -> composite key, for resolving NACK media sources.
    by_ssrc: std.AutoHashMapUnmanaged(u32, []const u8) = .empty,
    /// Channel -> per-call SRTP group key (SDES). One key per active call,
    /// distributed to every participant; dropped when the call empties.
    group_keys: std.StringHashMapUnmanaged([group_key_len]u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) MediaTransport {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *MediaTransport) void {
        var it = self.endpoints.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            e.value_ptr.rtx.deinit();
        }
        self.endpoints.deinit(self.allocator);
        self.by_ufrag.deinit(self.allocator);
        self.by_addr.deinit(self.allocator);
        self.by_ssrc.deinit(self.allocator);
        var gk = self.group_keys.keyIterator();
        while (gk.next()) |k| self.allocator.free(k.*);
        self.group_keys.deinit(self.allocator);
        self.* = undefined;
    }

    fn compositeKey(buf: []u8, channel: []const u8, participant: []const u8) ?[]const u8 {
        if (channel.len + 1 + participant.len > buf.len) return null;
        @memcpy(buf[0..channel.len], channel);
        buf[channel.len] = 0;
        @memcpy(buf[channel.len + 1 ..][0..participant.len], participant);
        return buf[0 .. channel.len + 1 + participant.len];
    }

    fn fillCreds(rng: std.Random, ufrag: []u8, pwd: []u8) void {
        for (ufrag) |*c| c.* = ufrag_alphabet[rng.uintLessThan(usize, ufrag_alphabet.len)];
        for (pwd) |*c| c.* = ufrag_alphabet[rng.uintLessThan(usize, ufrag_alphabet.len)];
    }

    /// Allocate (or re-credential) the endpoint for `participant` in `channel`,
    /// generating a fresh ICE ufrag/pwd from `rng`. Returns a pointer to the
    /// stored endpoint. Re-allocating an existing participant rotates creds and
    /// clears any prior remote binding.
    pub fn allocate(
        self: *MediaTransport,
        channel: []const u8,
        participant: []const u8,
        rng: std.Random,
    ) !*Endpoint {
        var kb: [256]u8 = undefined;
        const k = compositeKey(&kb, channel, participant) orelse return error.NameTooLong;

        var ep = Endpoint{ .ufrag = undefined, .pwd = undefined, .rtx = rtp_nack.RetransmitBuffer.init(self.allocator, rtx_capacity) };
        fillCreds(rng, &ep.ufrag, &ep.pwd);

        const gop = try self.endpoints.getOrPut(self.allocator, k);
        if (!gop.found_existing) {
            gop.key_ptr.* = self.allocator.dupe(u8, k) catch |e| {
                _ = self.endpoints.remove(k);
                ep.rtx.deinit();
                return e;
            };
        } else {
            // Rotating creds: tear down the prior incarnation's indexes + buffer.
            _ = self.by_ufrag.remove(gop.value_ptr.ufrag);
            if (gop.value_ptr.remote) |a| _ = self.by_addr.remove(addrKey(a));
            if (gop.value_ptr.ssrc != 0) _ = self.by_ssrc.remove(gop.value_ptr.ssrc);
            gop.value_ptr.rtx.deinit();
        }
        gop.value_ptr.* = ep;
        // Index the ufrag by value back to the owned key.
        self.by_ufrag.put(self.allocator, gop.value_ptr.ufrag, gop.key_ptr.*) catch {};
        return gop.value_ptr;
    }

    pub fn get(self: *MediaTransport, channel: []const u8, participant: []const u8) ?*Endpoint {
        var kb: [256]u8 = undefined;
        const k = compositeKey(&kb, channel, participant) orelse return null;
        return self.endpoints.getPtr(k);
    }

    /// The channel that owns the participant bound to `source`, or null if the
    /// address is unknown. Lets the WebRTC relay learn an inbound RTP packet's
    /// channel (for cross-leg bridging). The returned slice borrows the composite
    /// endpoint key (valid while that endpoint exists).
    pub fn channelForSource(self: *MediaTransport, source: TransportAddress) ?[]const u8 {
        const composite = self.by_addr.get(addrKey(source)) orelse return null;
        const nul = std.mem.indexOfScalar(u8, composite, 0) orelse return composite;
        return composite[0..nul];
    }

    /// The full composite "channel\x00participant" key of the participant bound
    /// to `source`, or null if the address is unknown. Read-only view into the
    /// address index; the returned slice borrows the owned endpoint key (valid
    /// while that endpoint exists). Lets the DTLS layer resolve a peer address to
    /// its (channel, participant) for RFC 8122 fingerprint binding.
    pub fn compositeForSource(self: *MediaTransport, source: TransportAddress) ?[]const u8 {
        return self.by_addr.get(addrKey(source));
    }

    /// Resolve a participant endpoint from the server ufrag carried in a STUN
    /// binding's USERNAME (`<server-ufrag>:<peer-ufrag>`).
    pub fn byServerUfrag(self: *MediaTransport, server_ufrag: []const u8) ?*Endpoint {
        const key = self.by_ufrag.get(ufragKey(server_ufrag) orelse return null) orelse return null;
        return self.endpoints.getPtr(key);
    }

    /// Bind the peer's media address after a successful connectivity check, and
    /// (re)index it for RTP source routing.
    pub fn bindRemote(self: *MediaTransport, channel: []const u8, participant: []const u8, addr: TransportAddress) bool {
        var kb: [256]u8 = undefined;
        const k = compositeKey(&kb, channel, participant) orelse return false;
        const owned = self.endpoints.getKey(k) orelse return false;
        const ep = self.endpoints.getPtr(k).?;
        self.rebindAddr(ep, owned, addr);
        return true;
    }

    /// Point `ep.remote` at `addr`, refreshing the by_addr index from any prior
    /// binding to the (stable, owned) `owned_key`.
    fn rebindAddr(self: *MediaTransport, ep: *Endpoint, owned_key: []const u8, addr: TransportAddress) void {
        if (ep.remote) |old| _ = self.by_addr.remove(addrKey(old));
        ep.remote = addr;
        self.by_addr.put(self.allocator, addrKey(addr), owned_key) catch {};
    }

    /// Record the SSRC a participant publishes (best-effort; first packet wins
    /// unless overwritten).
    pub fn setSsrc(self: *MediaTransport, channel: []const u8, participant: []const u8, ssrc: u32) void {
        if (self.get(channel, participant)) |ep| ep.ssrc = ssrc;
    }

    /// Record the highest spatial layer `participant` will receive. False when
    /// that endpoint does not exist yet.
    pub fn setReceiverSpatial(self: *MediaTransport, channel: []const u8, participant: []const u8, max_spatial: u8) bool {
        const ep = self.get(channel, participant) orelse return false;
        ep.max_spatial = max_spatial;
        return true;
    }

    /// Fill `out` with the bound remote addresses of every *other* connected
    /// participant in `channel` whose spatial ceiling admits `spatial`.
    /// Returns how many were written. A receiver at a lower ceiling is skipped
    /// without changing anyone else's ceiling.
    pub fn forwardTargets(
        self: *MediaTransport,
        channel: []const u8,
        from: []const u8,
        spatial: u8,
        out: []TransportAddress,
    ) usize {
        var n: usize = 0;
        var it = self.endpoints.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            const sep = std.mem.indexOfScalar(u8, key, 0) orelse continue;
            if (!std.mem.eql(u8, key[0..sep], channel)) continue;
            if (std.mem.eql(u8, key[sep + 1 ..], from)) continue; // don't echo to sender
            if (spatial > entry.value_ptr.max_spatial) continue;
            const remote = entry.value_ptr.remote orelse continue;
            if (n >= out.len) break;
            out[n] = remote;
            n += 1;
        }
        return n;
    }

    /// Convert an ICE transport address into a STUN address (null if the IP
    /// length is neither 4 nor 16 octets).
    fn toStunAddress(a: TransportAddress) ?stun.Address {
        return switch (a.ip_len) {
            4 => .{ .ipv4 = .{ .ip = a.ip[0..4].*, .port = a.port } },
            16 => .{ .ipv6 = .{ .ip = a.ip[0..16].*, .port = a.port } },
            else => null,
        };
    }

    /// Process an inbound STUN binding request that arrived from `source` on the
    /// media socket. The request is demultiplexed to a participant via the
    /// server ufrag in its USERNAME (`<server-ufrag>:<peer-ufrag>`), its
    /// MESSAGE-INTEGRITY is verified against that endpoint's password, and on
    /// success the source is bound as the peer's media address and a binding
    /// success response (XOR-MAPPED-ADDRESS = source, MESSAGE-INTEGRITY,
    /// FINGERPRINT) is returned for the caller to send back. Returns null when
    /// the datagram is not an authenticated binding for a known endpoint (the
    /// caller drops it). The returned slice is owned by `allocator`.
    pub fn handleStunBinding(
        self: *MediaTransport,
        allocator: std.mem.Allocator,
        datagram: []const u8,
        source: TransportAddress,
    ) !?[]u8 {
        var msg = stun.decode(allocator, datagram) catch return null;
        defer msg.deinit(allocator);
        if (msg.typ != .binding_request) return null;

        // Pull the USERNAME and isolate the server ufrag (before the ':').
        var username: ?[]const u8 = null;
        for (msg.attributes) |attr| {
            if (attr == .username) username = attr.username;
        }
        const user = username orelse return null;
        const colon = std.mem.indexOfScalar(u8, user, ':') orelse user.len;
        const server_ufrag = user[0..colon];

        const owned_key = self.by_ufrag.get(ufragKey(server_ufrag) orelse return null) orelse return null;
        const ep = self.endpoints.getPtr(owned_key) orelse return null;
        // Short-term credential check (RFC 8445 §7.3): the peer keys its request
        // with the server's advertised password.
        const ok = stun.verifyMessageIntegrity(datagram, ep.pwdSlice()) catch return null;
        if (!ok) return null;

        self.rebindAddr(ep, owned_key, source); // connectivity confirmed → bind + index

        const mapped = toStunAddress(source) orelse return null;
        return try stun.buildBindingSuccessResponse(allocator, msg.transaction_id, .{
            .xor_mapped_address = mapped,
            .integrity_key = ep.pwdSlice(),
            .fingerprint = true,
        });
    }

    /// Route an inbound RTP/RTCP datagram by its UDP `source`: resolve the
    /// sending participant via the address index, meter it (`bytes_len`), then
    /// fill `out` with the bound remotes of every *other* connected participant
    /// in the same call (the SFU relay set). Returns 0 if the source is not a
    /// known bound endpoint.
    /// `packet` is the full inbound datagram (metered + RTP-cached for NACK).
    /// `ssrc` (0 = unknown/RTCP) is learned onto the sending endpoint the first
    /// time it is seen, and indexed for NACK source resolution. `seq` non-null
    /// (RTP only) caches the packet for retransmission.
    pub fn forwardFromSource(self: *MediaTransport, source: TransportAddress, packet: []const u8, ssrc: u32, seq: ?u16, out: []TransportAddress) usize {
        const key = self.by_addr.get(addrKey(source)) orelse return 0;
        if (self.endpoints.getPtr(key)) |ep| {
            ep.rx_packets += 1;
            ep.rx_bytes += packet.len;
            if (ssrc != 0 and ep.ssrc == 0) {
                ep.ssrc = ssrc;
                self.by_ssrc.put(self.allocator, ssrc, key) catch {};
            }
            if (seq) |s| ep.rtx.onSent(s, packet) catch {};
        }
        const sep = std.mem.indexOfScalar(u8, key, 0) orelse return 0;
        return self.forwardTargets(key[0..sep], key[sep + 1 ..], rtpSpatialLayer(packet), out);
    }

    /// Spatial layer from the one-byte RTP extension. No extension, a short
    /// packet, or a parse failure is layer 0 so an unmarked packet still
    /// reaches every receiver.
    fn rtpSpatialLayer(packet: []const u8) u8 {
        const data = rtp_ext.find(packet, rtp_ext.spatial_layer_id) catch return 0;
        const bytes = data orelse return 0;
        if (bytes.len != 1) return 0;
        return bytes[0];
    }

    /// Copy a cached RTP packet (by media SSRC + sequence) into `out` for NACK
    /// retransmission, returning its length, or null if not retained. The cached
    /// packet's own header SSRC MUST equal `media_ssrc`: the retransmit buffer is
    /// seq-keyed and an endpoint may publish multiple SSRCs (e.g. simulcast
    /// audio+video sharing the seq space), so returning a different-SSRC packet
    /// would let a caller re-protect it under a nonce that disagrees with its
    /// replay-window key. Reject the mismatch rather than emit a wrong packet.
    pub fn copyRetransmit(self: *MediaTransport, media_ssrc: u32, seq: u16, out: []u8) ?usize {
        const key = self.by_ssrc.get(media_ssrc) orelse return null;
        const ep = self.endpoints.getPtr(key) orelse return null;
        const bytes = ep.rtx.lookup(seq) orelse return null;
        if (bytes.len > out.len) return null;
        if (bytes.len < srtp.rtp_header_len) return null;
        if (std.mem.readInt(u32, bytes[8..12], .big) != media_ssrc) return null;
        @memcpy(out[0..bytes.len], bytes);
        return bytes.len;
    }

    /// Per-participant transport stats snapshot (copied out so callers need not
    /// hold a lock while formatting).
    pub const ParticipantStat = struct {
        name_buf: [64]u8 = undefined,
        name_len: usize = 0,
        connected: bool = false,
        ssrc: u32 = 0,
        rx_packets: u64 = 0,
        rx_bytes: u64 = 0,

        pub fn name(self: *const ParticipantStat) []const u8 {
            return self.name_buf[0..self.name_len];
        }
    };

    /// Fill `out` with a stats snapshot for each participant in `channel`.
    pub fn statsForChannel(self: *MediaTransport, channel: []const u8, out: []ParticipantStat) usize {
        var n: usize = 0;
        var it = self.endpoints.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            const sep = std.mem.indexOfScalar(u8, key, 0) orelse continue;
            if (!std.mem.eql(u8, key[0..sep], channel)) continue;
            if (n >= out.len) break;
            const who = key[sep + 1 ..];
            var s = ParticipantStat{
                .connected = entry.value_ptr.connected(),
                .ssrc = entry.value_ptr.ssrc,
                .rx_packets = entry.value_ptr.rx_packets,
                .rx_bytes = entry.value_ptr.rx_bytes,
            };
            const len = @min(who.len, s.name_buf.len);
            @memcpy(s.name_buf[0..len], who[0..len]);
            s.name_len = len;
            out[n] = s;
            n += 1;
        }
        return n;
    }

    /// The per-call SRTP group key for `channel`, generating and storing a fresh
    /// one (from `rng`) on first use. The same key is returned for every
    /// participant in the call until it empties.
    pub fn ensureGroupKey(self: *MediaTransport, channel: []const u8, rng: std.Random) [group_key_len]u8 {
        if (self.group_keys.getPtr(channel)) |k| return k.*;
        var key: [group_key_len]u8 = undefined;
        rng.bytes(&key);
        const gop = self.group_keys.getOrPut(self.allocator, channel) catch return key;
        if (!gop.found_existing) {
            gop.key_ptr.* = self.allocator.dupe(u8, channel) catch {
                _ = self.group_keys.remove(channel);
                return key;
            };
            gop.value_ptr.* = key;
        }
        return gop.value_ptr.*;
    }

    /// Whether any participant endpoint remains in `channel`.
    fn channelHasEndpoints(self: *MediaTransport, channel: []const u8) bool {
        var it = self.endpoints.keyIterator();
        while (it.next()) |k| {
            const key = k.*;
            const sep = std.mem.indexOfScalar(u8, key, 0) orelse continue;
            if (std.mem.eql(u8, key[0..sep], channel)) return true;
        }
        return false;
    }

    fn dropGroupKeyIfEmpty(self: *MediaTransport, channel: []const u8) void {
        if (self.channelHasEndpoints(channel)) return;
        if (self.group_keys.fetchRemove(channel)) |kv| self.allocator.free(kv.key);
    }

    /// Drop a participant's endpoint (on MEDIA LEAVE / disconnect). The call's
    /// SRTP group key is released once the last participant leaves.
    pub fn remove(self: *MediaTransport, channel: []const u8, participant: []const u8) void {
        var kb: [256]u8 = undefined;
        const k = compositeKey(&kb, channel, participant) orelse return;
        if (self.endpoints.fetchRemove(k)) |kv| {
            var ep = kv.value;
            _ = self.by_ufrag.remove(ep.ufrag);
            if (ep.remote) |addr| _ = self.by_addr.remove(addrKey(addr));
            if (ep.ssrc != 0) _ = self.by_ssrc.remove(ep.ssrc);
            ep.rtx.deinit();
            self.allocator.free(kv.key);
        }
        self.dropGroupKeyIfEmpty(channel);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testAddr(last_octet: u8, port: u16) TransportAddress {
    return TransportAddress.fromBytes(&[_]u8{ 192, 168, 0, last_octet }, port) catch unreachable;
}

test "allocate issues distinct creds and indexes by ufrag" {
    var prng = std.Random.DefaultPrng.init(0x1234);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();

    const a = try mt.allocate("#call", "alice", prng.random());
    try testing.expectEqual(@as(usize, ufrag_len), a.ufragSlice().len);
    try testing.expectEqual(@as(usize, pwd_len), a.pwdSlice().len);
    try testing.expect(!a.connected());

    const a_ufrag = a.ufrag; // copy before more inserts (pointer may move)
    _ = try mt.allocate("#call", "bob", prng.random());

    // The server ufrag demuxes back to the right participant.
    const found = mt.byServerUfrag(&a_ufrag) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &a_ufrag, found.ufragSlice());
}

test "forwardTargets returns other connected peers only" {
    var prng = std.Random.DefaultPrng.init(7);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();
    _ = try mt.allocate("#c", "alice", prng.random());
    _ = try mt.allocate("#c", "bob", prng.random());
    _ = try mt.allocate("#c", "carol", prng.random());
    _ = try mt.allocate("#other", "dave", prng.random());

    // No one is connected yet -> empty forward set.
    var out: [8]TransportAddress = undefined;
    try testing.expectEqual(@as(usize, 0), mt.forwardTargets("#c", "alice", 0, &out));

    try testing.expect(mt.bindRemote("#c", "bob", testAddr(2, 5002)));
    try testing.expect(mt.bindRemote("#c", "carol", testAddr(3, 5003)));
    try testing.expect(mt.bindRemote("#other", "dave", testAddr(9, 5009)));

    // alice's packet forwards to bob+carol (connected, same channel), not dave.
    const n = mt.forwardTargets("#c", "alice", 0, &out);
    try testing.expectEqual(@as(usize, 2), n);
    for (out[0..n]) |addr| try testing.expect(addr.port == 5002 or addr.port == 5003);
}

test "channelForSource resolves the channel of a bound peer address" {
    var prng = std.Random.DefaultPrng.init(11);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();
    _ = try mt.allocate("#call", "alice", prng.random());
    try testing.expect(mt.bindRemote("#call", "alice", testAddr(7, 6001)));

    const chan = mt.channelForSource(testAddr(7, 6001)) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("#call", chan);
    // an unbound address resolves to null
    try testing.expect(mt.channelForSource(testAddr(8, 9999)) == null);
}

test "compositeForSource resolves the full channel\\0participant key of a bound peer" {
    var prng = std.Random.DefaultPrng.init(13);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();
    _ = try mt.allocate("#call", "alice", prng.random());
    try testing.expect(mt.bindRemote("#call", "alice", testAddr(7, 6100)));

    const composite = mt.compositeForSource(testAddr(7, 6100)) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, "#call\x00alice", composite);
    // an unbound address resolves to null
    try testing.expect(mt.compositeForSource(testAddr(8, 9999)) == null);
}

test "handleStunBinding authenticates, binds the peer, and answers" {
    var prng = std.Random.DefaultPrng.init(0xfeed);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();
    const ep = try mt.allocate("#c", "alice", prng.random());
    const ufrag = ep.ufrag;
    const pwd = ep.pwd;

    // Client builds a binding request: USERNAME=<server>:<peer>, keyed by pwd.
    var user_buf: [ufrag_len + 6]u8 = undefined;
    const user = std.fmt.bufPrint(&user_buf, "{s}:peer", .{ufrag[0..]}) catch unreachable;
    const tx: stun.TransactionId = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    const req = try stun.buildBindingRequest(testing.allocator, tx, .{
        .username = user,
        .integrity_key = pwd[0..],
        .fingerprint = true,
    });
    defer testing.allocator.free(req);

    const src = testAddr(7, 50007);
    const resp = (try mt.handleStunBinding(testing.allocator, req, src)) orelse return error.TestUnexpectedResult;
    defer testing.allocator.free(resp);

    // Peer address is now bound, and it is the SFU forward target for others.
    try testing.expect(mt.get("#c", "alice").?.connected());
    try testing.expectEqual(@as(u16, 50007), mt.get("#c", "alice").?.remote.?.port);

    // The response is a success with a verifiable MESSAGE-INTEGRITY.
    var decoded = try stun.decode(testing.allocator, resp);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(stun.MessageType.binding_success_response, decoded.typ);
    try testing.expect(try stun.verifyMessageIntegrity(resp, pwd[0..]));
}

test "handleStunBinding rejects bad integrity and unknown ufrag" {
    var prng = std.Random.DefaultPrng.init(0xabcd);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();
    const ep = try mt.allocate("#c", "alice", prng.random());
    const ufrag = ep.ufrag;

    const tx: stun.TransactionId = .{ 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9 };
    var user_buf: [ufrag_len + 6]u8 = undefined;
    const user = std.fmt.bufPrint(&user_buf, "{s}:peer", .{ufrag[0..]}) catch unreachable;

    // Wrong password -> integrity fails -> dropped (null), no binding.
    const bad = try stun.buildBindingRequest(testing.allocator, tx, .{
        .username = user,
        .integrity_key = "wrong-password",
        .fingerprint = true,
    });
    defer testing.allocator.free(bad);
    try testing.expect((try mt.handleStunBinding(testing.allocator, bad, testAddr(1, 1))) == null);
    try testing.expect(!mt.get("#c", "alice").?.connected());

    // Unknown ufrag -> dropped.
    const unknown = try stun.buildBindingRequest(testing.allocator, tx, .{
        .username = "ZZZZZZZZ:peer",
        .integrity_key = "whatever",
        .fingerprint = true,
    });
    defer testing.allocator.free(unknown);
    try testing.expect((try mt.handleStunBinding(testing.allocator, unknown, testAddr(1, 1))) == null);
}

test "forwardFromSource routes an RTP packet to the other peers" {
    var prng = std.Random.DefaultPrng.init(0x5151);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();
    _ = try mt.allocate("#c", "alice", prng.random());
    _ = try mt.allocate("#c", "bob", prng.random());
    _ = try mt.allocate("#c", "carol", prng.random());

    const alice_addr = testAddr(1, 5001);
    try testing.expect(mt.bindRemote("#c", "alice", alice_addr));
    try testing.expect(mt.bindRemote("#c", "bob", testAddr(2, 5002)));
    try testing.expect(mt.bindRemote("#c", "carol", testAddr(3, 5003)));

    // An RTP packet from alice (ssrc 0xAA, seq 7) forwards to bob+carol, not
    // alice; it is also SSRC-indexed and cached for NACK.
    const pkt = [_]u8{ 0x80, 0x60, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0xAA, 1, 2, 3 };
    var out: [8]TransportAddress = undefined;
    const n = mt.forwardFromSource(alice_addr, &pkt, 0xAA, 7, &out);
    try testing.expectEqual(@as(usize, 2), n);
    for (out[0..n]) |a| try testing.expect(a.port == 5002 or a.port == 5003);

    // NACK for alice's ssrc + seq 7 retrieves the cached packet.
    var rtx: [64]u8 = undefined;
    const got = mt.copyRetransmit(0xAA, 7, &rtx) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &pkt, rtx[0..got]);
    try testing.expect(mt.copyRetransmit(0xAA, 99, &rtx) == null); // seq not cached

    // An unknown source routes nowhere.
    try testing.expectEqual(@as(usize, 0), mt.forwardFromSource(testAddr(9, 9999), &pkt, 0, null, &out));

    // After alice leaves, her address and ssrc no longer resolve.
    mt.remove("#c", "alice");
    try testing.expectEqual(@as(usize, 0), mt.forwardFromSource(alice_addr, &pkt, 0, null, &out));
    try testing.expect(mt.copyRetransmit(0xAA, 7, &rtx) == null);
}

test "copyRetransmit rejects a cached packet whose header SSRC differs from the request" {
    var prng = std.Random.DefaultPrng.init(0x7ac0);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();
    _ = try mt.allocate("#c", "alice", prng.random());
    const alice = testAddr(1, 5001);
    try testing.expect(mt.bindRemote("#c", "alice", alice));
    _ = try mt.allocate("#c", "bob", prng.random());
    try testing.expect(mt.bindRemote("#c", "bob", testAddr(2, 5002)));

    // Alice publishes ssrc 0xAA (seq 10) — indexed for NACK — and, on the same
    // 5-tuple, a second stream ssrc 0xBB (seq 11). The retransmit cache is
    // seq-keyed, so both land in alice's buffer; only 0xAA is SSRC-indexed.
    const pkt_aa = [_]u8{ 0x80, 0x60, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0xAA, 1, 2, 3 };
    const pkt_bb = [_]u8{ 0x80, 0x60, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0xBB, 4, 5, 6 };
    var out: [8]TransportAddress = undefined;
    _ = mt.forwardFromSource(alice, &pkt_aa, 0xAA, 10, &out);
    _ = mt.forwardFromSource(alice, &pkt_bb, 0xBB, 11, &out);

    var rtx: [64]u8 = undefined;
    // A NACK for 0xAA/10 returns the matching packet.
    const ok = mt.copyRetransmit(0xAA, 10, &rtx) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &pkt_aa, rtx[0..ok]);
    // A NACK for 0xAA/11 must NOT return the 0xBB-header packet cached at seq 11.
    try testing.expect(mt.copyRetransmit(0xAA, 11, &rtx) == null);
}

fn writeSpatialRtp(spatial: u8, seq: u16, out: []u8) usize {
    var ext_buf: [16]u8 = undefined;
    var layer = [_]u8{spatial};
    const ext = rtp_ext.buildOneByteExtension(&.{.{ .id = rtp_ext.spatial_layer_id, .data = &layer }}, &ext_buf) catch unreachable;
    out[0] = 0x90;
    out[1] = 96;
    std.mem.writeInt(u16, out[2..4], seq, .big);
    @memset(out[4..12], 0);
    @memcpy(out[12..][0..ext.len], ext);
    out[12 + ext.len] = 0xAB;
    return 13 + ext.len;
}

test "GAP-V3 two receivers keep independent spatial layers" {
    var prng = std.Random.DefaultPrng.init(0x0A3);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();
    _ = try mt.allocate("#v", "pub", prng.random());
    _ = try mt.allocate("#v", "low", prng.random());
    _ = try mt.allocate("#v", "high", prng.random());
    const pub_addr = testAddr(1, 7001);
    try testing.expect(mt.bindRemote("#v", "pub", pub_addr));
    try testing.expect(mt.bindRemote("#v", "low", testAddr(2, 7002)));
    try testing.expect(mt.bindRemote("#v", "high", testAddr(3, 7003)));
    try testing.expect(mt.setReceiverSpatial("#v", "low", 0));
    try testing.expect(mt.setReceiverSpatial("#v", "high", 2));
    try testing.expectEqual(@as(usize, 512), rtx_capacity);

    var pkt: [64]u8 = undefined;
    var out: [8]TransportAddress = undefined;

    const high_len = writeSpatialRtp(2, 1, &pkt);
    const high_n = mt.forwardFromSource(pub_addr, pkt[0..high_len], 0xA1, 1, &out);
    try testing.expectEqual(@as(usize, 1), high_n);
    try testing.expectEqual(@as(u16, 7003), out[0].port);

    const base_len = writeSpatialRtp(0, 2, &pkt);
    const base_n = mt.forwardFromSource(pub_addr, pkt[0..base_len], 0xA1, 2, &out);
    try testing.expectEqual(@as(usize, 2), base_n);

    // Lowering the high receiver does not pull the low receiver's ceiling,
    // and raising the low receiver does not pull the high one back up.
    try testing.expect(mt.setReceiverSpatial("#v", "high", 0));
    try testing.expectEqual(@as(u8, 0), mt.get("#v", "low").?.max_spatial);
    const dropped = writeSpatialRtp(2, 3, &pkt);
    try testing.expectEqual(@as(usize, 0), mt.forwardFromSource(pub_addr, pkt[0..dropped], 0xA1, 3, &out));
    try testing.expect(mt.setReceiverSpatial("#v", "low", 2));
    try testing.expectEqual(@as(u8, 0), mt.get("#v", "high").?.max_spatial);
    const only_low = mt.forwardFromSource(pub_addr, pkt[0..dropped], 0xA1, 4, &out);
    try testing.expectEqual(@as(usize, 1), only_low);
    try testing.expectEqual(@as(u16, 7002), out[0].port);

    std.debug.print("GAP-V3 branch=rtp per-receiver spatial ceiling from the packet layer; rtx cache {d} is the product, no separate RTX SSRC\n", .{rtx_capacity});
}

test "group key is stable per call and released when it empties" {
    var prng = std.Random.DefaultPrng.init(0x6abe);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();
    _ = try mt.allocate("#c", "alice", prng.random());
    _ = try mt.allocate("#c", "bob", prng.random());

    // Every participant in the same call gets the identical key...
    const k1 = mt.ensureGroupKey("#c", prng.random());
    const k2 = mt.ensureGroupKey("#c", prng.random());
    try testing.expectEqualSlices(u8, &k1, &k2);
    // ...but a different call gets a different key.
    _ = try mt.allocate("#d", "dave", prng.random());
    const kd = mt.ensureGroupKey("#d", prng.random());
    try testing.expect(!std.mem.eql(u8, &k1, &kd));

    // Key persists while participants remain, released when the last leaves.
    mt.remove("#c", "alice");
    try testing.expect(mt.group_keys.contains("#c"));
    mt.remove("#c", "bob");
    try testing.expect(!mt.group_keys.contains("#c"));
}

test "remove drops the endpoint and its ufrag index" {
    var prng = std.Random.DefaultPrng.init(99);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();
    const ep = try mt.allocate("#c", "alice", prng.random());
    const ufrag = ep.ufrag;
    try testing.expect(mt.byServerUfrag(&ufrag) != null);
    mt.remove("#c", "alice");
    try testing.expect(mt.get("#c", "alice") == null);
    try testing.expect(mt.byServerUfrag(&ufrag) == null);
}
