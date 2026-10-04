// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! RFC 8122 DTLS-SRTP peer-certificate fingerprint verification for the media
//! plane's DTLS terminators.
//!
//! WebRTC binds the SDP-signaled `a=fingerprint` to the certificate a peer
//! presents in the DTLS handshake. Onyx Server is the DTLS *server* (`setup:passive`),
//! so the browser is the DTLS client: the daemon must verify the browser's
//! presented certificate against the fingerprint the browser signaled in its
//! MEDIA OFFER. This module owns that binding (per remote transport address) and
//! the constant-time comparison, so the handshake-completion path can FAIL
//! CLOSED on a mismatch — withholding the exported SRTP keys entirely.
//!
//! Scope note (Increment 3): the DTLS 1.2/1.3 terminators are today
//! server-authenticated only — they do not yet emit a CertificateRequest nor
//! capture/possession-verify the browser's client certificate (that is a
//! companion terminator-increment change, since it touches the handshake
//! signature crypto). `recordPeerCert` is the seam the terminator calls the
//! moment client-certificate capture lands. Until then, when an expected
//! fingerprint is bound but no peer certificate has been recorded, the peer is
//! UNVERIFIED and the terminator's `exportedKeys`/`srtpProfile` return null
//! (fail closed): a fingerprint that cannot be verified yields no media.

const std = @import("std");
const TransportAddress = @import("ice.zig").TransportAddress;

const Sha256 = std.crypto.hash.sha2.Sha256;

/// Length of a SHA-256 certificate fingerprint (RFC 8122 sha-256), in bytes.
pub const digest_len = Sha256.digest_length; // 32

/// SHA-256 over a certificate's DER encoding — the raw bytes an RFC 8122
/// `a=fingerprint:sha-256 <colon-hex>` attribute renders.
pub fn certDigest(cert_der: []const u8) [digest_len]u8 {
    var d: [digest_len]u8 = undefined;
    Sha256.hash(cert_der, &d, .{});
    return d;
}

/// Equality of two 32-byte fingerprints. Both operands are public data; the
/// timing-safe compare is defensive hygiene (the code path is a security gate),
/// not the protection of a secret.
pub fn digestEql(a: [digest_len]u8, b: [digest_len]u8) bool {
    return std.crypto.timing_safe.eql([digest_len]u8, a, b);
}

/// Fixed-capacity table of expected peer fingerprints keyed by remote transport
/// address, sized to the terminator's session table so every in-flight peer can
/// hold one binding. No allocation; a terminator embeds it by value. Lifetime is
/// decoupled from the session slots (a binding is set the moment the signaling
/// layer learns the peer address, before the ClientHello creates a session).
pub fn Bindings(comptime capacity: usize) type {
    return struct {
        const Self = @This();
        const Slot = struct {
            addr: TransportAddress = .{},
            digest: [digest_len]u8 = @splat(0),
            active: bool = false,
            /// Monotonic bind order, for stalest-first eviction on a full table.
            stamp: u64 = 0,
        };
        slots: [capacity]Slot = @splat(.{}),
        /// Monotonic tick incremented on every bind; the per-slot `stamp` snapshot
        /// records recency so a full table evicts its oldest binding.
        tick: u64 = 0,
        /// Callers can discard bind's bool. Preserve a refused last-counter
        /// bind as negative authority, so absent expectations cannot allow keys.
        exhausted: bool = false,

        /// Exact source-owned binding facts, including cleared-slot recency.
        /// This describes expectations, never proof that a peer authenticated.
        /// The containing terminator must separately validate session/auth joins
        /// under an authenticated aggregate capsule and frozen signaling cut.
        pub const Snapshot = struct {
            pub const Entry = struct {
                addr: TransportAddress,
                digest: [digest_len]u8,
                active: bool,
                stamp: u64,
            };
            entries: [capacity]Entry,
            tick: u64,
            exhausted: bool,

            pub fn deinit(self: *Snapshot) void {
                for (&self.entries) |*entry| std.crypto.secureZero(u8, &entry.digest);
                self.* = undefined;
            }

            pub fn validate(self: *const Snapshot) !void {
                if (self.exhausted and self.tick != std.math.maxInt(u64)) return error.InvalidSnapshot;
                for (&self.entries, 0..) |entry, i| {
                    if (entry.stamp > self.tick) return error.InvalidSnapshot;
                    if (entry.addr.ip_len == 0) {
                        if (entry.active or entry.stamp != 0 or entry.addr.port != 0 or
                            !std.mem.allEqual(u8, &entry.addr.ip, 0)) return error.InvalidSnapshot;
                    } else {
                        if (entry.addr.ip_len != 4 and entry.addr.ip_len != 16) return error.InvalidSnapshot;
                        if (entry.addr.port == 0 or entry.stamp == 0 or
                            !std.mem.allEqual(u8, entry.addr.ip[entry.addr.ip_len..], 0)) return error.InvalidSnapshot;
                    }
                    if (!entry.active and !std.mem.allEqual(u8, &entry.digest, 0)) return error.InvalidSnapshot;
                    if (entry.active) for (self.entries[0..i]) |previous| {
                        if (previous.active and (previous.addr.eql(entry.addr) or previous.stamp == entry.stamp)) return error.InvalidSnapshot;
                    };
                }
            }
        };

        pub fn capture(self: *const Self) !Snapshot {
            var snapshot: Snapshot = undefined;
            snapshot.tick = self.tick;
            snapshot.exhausted = self.exhausted;
            for (&snapshot.entries, &self.slots) |*entry, slot| {
                entry.* = .{ .addr = slot.addr, .digest = slot.digest, .active = slot.active, .stamp = slot.stamp };
            }
            errdefer snapshot.deinit();
            try snapshot.validate();
            return snapshot;
        }

        /// Detached value candidate. No bind/rebind, tick increment, allocation,
        /// signaling callback or changes to an existing owner occur here.
        pub fn prepareRestore(snapshot: *const Snapshot) !Self {
            try snapshot.validate();
            var candidate: Self = .{ .tick = snapshot.tick, .exhausted = snapshot.exhausted };
            for (&candidate.slots, &snapshot.entries) |*slot, entry| {
                slot.* = .{ .addr = entry.addr, .digest = entry.digest, .active = entry.active, .stamp = entry.stamp };
            }
            return candidate;
        }

        /// Bind (or update) the expected fingerprint for `addr`. Idempotent for a
        /// repeated address. ALWAYS records the expectation — a signaled
        /// fingerprint must never silently vanish (which would let a peer read as
        /// "verification not required" and export keys UNVERIFIED). On a full
        /// table with a new address it evicts the STALEST binding; the terminator
        /// backstops any peer whose binding is evicted after its flight via a
        /// per-session "mutual auth required" flag, so eviction can never open a
        /// fail-open hole. Returns true on success (always, barring a zero-capacity
        /// table), false when capacity is zero or chronology is exhausted.
        /// Exhaustion latches a denial that every terminator must honor.
        pub fn bind(self: *Self, addr: TransportAddress, digest: [digest_len]u8) bool {
            if (self.slots.len == 0) return false;
            if (self.exhausted or self.tick == std.math.maxInt(u64)) {
                self.exhausted = true;
                return false;
            }
            self.tick += 1;
            var free: ?*Slot = null;
            var stalest: *Slot = &self.slots[0];
            for (&self.slots) |*s| {
                if (s.active and s.addr.eql(addr)) {
                    s.digest = digest;
                    s.stamp = self.tick;
                    return true;
                }
                if (!s.active) {
                    if (free == null) free = s;
                } else if (s.stamp < stalest.stamp) {
                    stalest = s;
                }
            }
            const slot = free orelse stalest;
            // Evicting another peer's live binding: secure-zero the stale digest.
            if (slot.active and !slot.addr.eql(addr)) std.crypto.secureZero(u8, &slot.digest);
            slot.* = .{ .addr = addr, .digest = digest, .active = true, .stamp = self.tick };
            return true;
        }

        /// The expected fingerprint bound for `addr`, or null if none.
        pub fn expectedFor(self: *const Self, addr: TransportAddress) ?[digest_len]u8 {
            for (&self.slots) |*s| {
                if (s.active and s.addr.eql(addr)) return s.digest;
            }
            return null;
        }

        /// Release the binding for `addr` (peer gone / session slot reused for a
        /// new address). Secure-zeros the stored digest.
        pub fn clear(self: *Self, addr: TransportAddress) void {
            for (&self.slots) |*s| {
                if (s.active and s.addr.eql(addr)) {
                    s.active = false;
                    std.crypto.secureZero(u8, &s.digest);
                    return;
                }
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testAddr(last: u8, port: u16) TransportAddress {
    return TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, last }, port) catch unreachable;
}

test "certDigest matches std SHA-256" {
    const der = "onyx dtls peer certificate DER";
    var expected: [digest_len]u8 = undefined;
    Sha256.hash(der, &expected, .{});
    try testing.expectEqualSlices(u8, &expected, &certDigest(der));
}

test "digestEql distinguishes match from a single-bit flip" {
    const a = certDigest("cert-a");
    var b = a;
    try testing.expect(digestEql(a, b));
    b[0] ^= 0x01;
    try testing.expect(!digestEql(a, b));
}

test "Bindings: bind, lookup, idempotent update, and clear" {
    var b: Bindings(4) = .{};
    const a1 = testAddr(1, 5000);
    const a2 = testAddr(2, 5000);
    const d1 = certDigest("one");
    const d2 = certDigest("two");

    try testing.expect(b.expectedFor(a1) == null);
    try testing.expect(b.bind(a1, d1));
    try testing.expect(b.bind(a2, d2));
    try testing.expectEqualSlices(u8, &d1, &(b.expectedFor(a1).?));
    try testing.expectEqualSlices(u8, &d2, &(b.expectedFor(a2).?));

    // Re-binding the same address updates in place (no new slot consumed).
    const d1b = certDigest("one-prime");
    try testing.expect(b.bind(a1, d1b));
    try testing.expectEqualSlices(u8, &d1b, &(b.expectedFor(a1).?));

    b.clear(a1);
    try testing.expect(b.expectedFor(a1) == null);
    // a2 is unaffected.
    try testing.expectEqualSlices(u8, &d2, &(b.expectedFor(a2).?));
}

test "Bindings: a full table evicts the stalest binding rather than dropping a new one" {
    var b: Bindings(2) = .{};
    const a1 = testAddr(1, 6000);
    const a2 = testAddr(2, 6000);
    const a3 = testAddr(3, 6000);
    try testing.expect(b.bind(a1, certDigest("1"))); // stamp 1 (stalest)
    try testing.expect(b.bind(a2, certDigest("2"))); // stamp 2
    // Table full + new address: the expectation is ALWAYS recorded (a signaled
    // fingerprint must never silently vanish). The STALEST binding (a1) is
    // evicted; the terminator's per-session mutual-auth flag keeps any peer whose
    // binding is evicted after its flight fail-closed.
    try testing.expect(b.bind(a3, certDigest("3")));
    try testing.expectEqualSlices(u8, &certDigest("3"), &(b.expectedFor(a3).?));
    try testing.expect(b.expectedFor(a1) == null); // evicted (stalest)
    try testing.expectEqualSlices(u8, &certDigest("2"), &(b.expectedFor(a2).?)); // untouched

    // A known address is still updated in place (no eviction, no new slot).
    const d2b = certDigest("2-prime");
    try testing.expect(b.bind(a2, d2b));
    try testing.expectEqualSlices(u8, &d2b, &(b.expectedFor(a2).?));
    try testing.expectEqualSlices(u8, &certDigest("3"), &(b.expectedFor(a3).?));
}

test "active media DTO fingerprint binding keeps exact cleared slot recency and next eviction" {
    const Table = Bindings(3);
    var source: Table = .{};
    const a = testAddr(1, 5001);
    const b = testAddr(2, 5002);
    const c = testAddr(3, 5003);
    const d = testAddr(4, 5004);
    try testing.expect(source.bind(a, certDigest("a")));
    try testing.expect(source.bind(b, certDigest("b")));
    source.clear(a);
    var snapshot = try source.capture();
    defer snapshot.deinit();
    var candidate = try Table.prepareRestore(&snapshot);
    try testing.expectEqualDeep(source, candidate);
    try testing.expect(candidate.expectedFor(a) == null);
    try testing.expectEqualDeep(source.expectedFor(b), candidate.expectedFor(b));
    try testing.expect(source.bind(c, certDigest("c")));
    try testing.expect(candidate.bind(c, certDigest("c")));
    try testing.expect(source.bind(a, certDigest("a2")));
    try testing.expect(candidate.bind(a, certDigest("a2")));
    try testing.expect(source.bind(d, certDigest("d")));
    try testing.expect(candidate.bind(d, certDigest("d")));
    try testing.expectEqualDeep(source, candidate);
    try testing.expect(candidate.expectedFor(b) == null);
}

test "active media DTO fingerprint binding refuses duplicate and malformed expectations without OLD mutation" {
    const Table = Bindings(2);
    var source: Table = .{};
    try testing.expect(source.bind(testAddr(1, 4001), certDigest("one")));
    try testing.expect(source.bind(testAddr(2, 4002), certDigest("two")));
    const old = source;
    var snapshot = try source.capture();
    defer snapshot.deinit();
    const saved = snapshot;
    snapshot.entries[1].addr = snapshot.entries[0].addr;
    try testing.expectError(error.InvalidSnapshot, Table.prepareRestore(&snapshot));
    snapshot = saved;
    snapshot.entries[1].stamp = snapshot.tick + 1;
    try testing.expectError(error.InvalidSnapshot, Table.prepareRestore(&snapshot));
    snapshot = saved;
    snapshot.entries[1].addr.ip_len = 17;
    try testing.expectError(error.InvalidSnapshot, Table.prepareRestore(&snapshot));
    snapshot = saved;
    snapshot.entries[1].active = false;
    try testing.expectError(error.InvalidSnapshot, Table.prepareRestore(&snapshot));
    try testing.expectEqualDeep(old, source);
    snapshot = saved;
    var candidate = try Table.prepareRestore(&snapshot);
    snapshot.deinit();
    snapshot = saved; // Restore cleanup custody; candidate has no borrowed bytes.
    try testing.expectEqualDeep(source, candidate);
    candidate.clear(testAddr(1, 4001));
    try testing.expect(source.expectedFor(testAddr(1, 4001)) != null);
}

test "active media DTO exhausted binding preserves prior facts and negative latch through restore" {
    const Table = Bindings(2);
    var source: Table = .{};
    const a = testAddr(1, 4011);
    const b = testAddr(2, 4012);
    try testing.expect(source.bind(a, certDigest("a")));
    source.tick = std.math.maxInt(u64);
    const slots = source.slots;
    try testing.expect(!source.bind(b, certDigest("b")));
    try testing.expect(source.exhausted);
    try testing.expectEqualDeep(slots, source.slots);
    try testing.expectEqual(std.math.maxInt(u64), source.tick);
    var snapshot = try source.capture();
    defer snapshot.deinit();
    var candidate = try Table.prepareRestore(&snapshot);
    try testing.expectEqualDeep(source, candidate);
    candidate.clear(a);
    try testing.expect(candidate.exhausted);
    try testing.expect(!candidate.bind(a, certDigest("again")));
    snapshot.tick = 1;
    try testing.expectError(error.InvalidSnapshot, Table.prepareRestore(&snapshot));
    snapshot.tick = std.math.maxInt(u64);
    try testing.expectEqualDeep(source, try Table.prepareRestore(&snapshot));
}

/// Canonical continuation of a running SHA-256 transcript. Only the defined
/// streaming prefix is copied; unused SDK buffer bytes/padding are not carried.
pub const TranscriptState = struct {
    words: [8]u32,
    buffer: [64]u8,
    buffered: u8,
    total: u64,

    pub fn capture(source: *const Sha256) !TranscriptState {
        if (source.buf_len >= 64 or source.total_len % 64 != source.buf_len) return error.InvalidSnapshot;
        var state: TranscriptState = .{ .words = source.s, .buffer = @splat(0), .buffered = source.buf_len, .total = source.total_len };
        @memcpy(state.buffer[0..source.buf_len], source.buf[0..source.buf_len]);
        return state;
    }
    pub fn validate(self: *const TranscriptState) !void {
        if (self.buffered >= 64 or self.total % 64 != self.buffered) return error.InvalidSnapshot;
        for (self.buffer[self.buffered..]) |byte| if (byte != 0) return error.InvalidSnapshot;
    }
    pub fn restore(self: *const TranscriptState) !Sha256 {
        try self.validate();
        return .{ .s = self.words, .buf = self.buffer, .buf_len = self.buffered, .total_len = self.total };
    }
    pub fn wipe(self: *TranscriptState) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

/// Exact retained future CSPRNG stream; restoration neither obtains entropy
/// nor derives a replacement seed. This is source state, not a public codec.
pub const RandomState = struct {
    state: [512]u8,
    offset: u16,
    pub fn capture(source: *const std.Random.DefaultCsprng) !RandomState {
        if (source.offset > 480) return error.InvalidSnapshot;
        const state: RandomState = .{ .state = source.state, .offset = @intCast(source.offset) };
        try state.validate();
        return state;
    }
    pub fn validate(self: *const RandomState) !void {
        if (self.offset > self.state.len - std.Random.DefaultCsprng.secret_seed_length) return error.InvalidSnapshot;
        for (self.state[std.Random.DefaultCsprng.secret_seed_length..][0..self.offset]) |byte| if (byte != 0) return error.InvalidSnapshot;
    }
    pub fn restore(self: *const RandomState) !std.Random.DefaultCsprng {
        try self.validate();
        return .{ .state = self.state, .offset = self.offset };
    }
    pub fn wipe(self: *RandomState) void {
        std.crypto.secureZero(u8, &self.state);
        self.offset = 0;
    }
};

test "active media DTO transcript continuation and future random bytes preserve partial buffers" {
    var hash = Sha256.init(.{});
    hash.update("a partial old transcript");
    var snapshot = try TranscriptState.capture(&hash);
    defer snapshot.wipe();
    var restored = try snapshot.restore();
    hash.update(" joined continuation");
    restored.update(" joined continuation");
    try std.testing.expectEqualSlices(u8, &hash.peek(), &restored.peek());
    snapshot.buffer[snapshot.buffered] = 1;
    try std.testing.expectError(error.InvalidSnapshot, snapshot.restore());
    snapshot.buffer[snapshot.buffered] = 0;
    snapshot.total += 1;
    try std.testing.expectError(error.InvalidSnapshot, snapshot.restore());
    var rng = std.Random.DefaultCsprng.init(@splat(7));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&rng));
    var consumed: [19]u8 = undefined;
    rng.random().bytes(&consumed);
    var random = try RandomState.capture(&rng);
    defer random.wipe();
    var next = try random.restore();
    defer std.crypto.secureZero(u8, std.mem.asBytes(&next));
    var before: [601]u8 = undefined;
    var after: [601]u8 = undefined;
    rng.random().bytes(&before);
    next.random().bytes(&after);
    try std.testing.expectEqualSlices(u8, &before, &after);
    random.offset = 481;
    try std.testing.expectError(error.InvalidSnapshot, random.restore());
}

/// Shared DTLS server identity state. The configured digest comes from the
/// authenticated OLD owner inventory; a self-signed key alone grants nothing.
pub const EngineIdentity = struct {
    cert_der: [1024]u8,
    cert_len: u16,
    secret_key: [32]u8,
    public_key: [65]u8,
    cookie_secret: [32]u8,
    random: RandomState,

    pub fn capture(owner: anytype) !EngineIdentity {
        if (owner.cert_len == 0 or owner.cert_len > 1024) return error.InvalidSnapshot;
        var random = try RandomState.capture(&owner.csprng);
        defer random.wipe();
        var identity: EngineIdentity = .{ .cert_der = @splat(0), .cert_len = @intCast(owner.cert_len), .secret_key = owner.cert_key.secret_key.toBytes(), .public_key = owner.cert_key.public_key.toUncompressedSec1(), .cookie_secret = owner.cookie_secret, .random = random };
        errdefer identity.wipe();
        @memcpy(identity.cert_der[0..owner.cert_len], owner.certDer());
        try identity.validate(certDigest(owner.certDer()));
        return identity;
    }
    pub fn validate(self: *const EngineIdentity, expected_digest: [32]u8) !void {
        const ecdsa = @import("../crypto/ecdsa_p256.zig");
        const x509 = @import("../crypto/x509.zig");
        const verify = @import("../crypto/x509_verify.zig");
        if (self.cert_len == 0 or self.cert_len > self.cert_der.len) return error.InvalidSnapshot;
        for (self.cert_der[self.cert_len..]) |byte| if (byte != 0) return error.InvalidSnapshot;
        const der = self.cert_der[0..self.cert_len];
        if (!digestEql(expected_digest, certDigest(der))) return error.ConfigMismatch;
        try self.random.validate();
        var key = try ecdsa.KeyPair.fromSecretKey(try ecdsa.SecretKey.fromBytes(self.secret_key));
        defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
        if (!std.crypto.timing_safe.eql([65]u8, key.public_key.toUncompressedSec1(), self.public_key)) return error.InvalidSnapshot;
        const cert = try x509.parse(der);
        if (!std.mem.eql(u8, cert.der, der) or !std.mem.eql(u8, cert.subject_der, cert.issuer_der) or !std.mem.eql(u8, cert.subject_public_key, &self.public_key)) return error.InvalidSnapshot;
        const link = try verify.linkInfo(der);
        try verify.verifyCertSignature(link.tbs_der, link.signature_der, link.sig_alg_oid, link.sig_alg_params, link.spki_der);
    }
    pub fn wipe(self: *EngineIdentity) void {
        std.crypto.secureZero(u8, &self.secret_key);
        std.crypto.secureZero(u8, &self.cookie_secret);
        self.random.wipe();
    }
};

pub const EnginePolicy = struct {
    cert_digest: [32]u8,
    session_capacity: usize,
    request_client_cert: bool,
};
