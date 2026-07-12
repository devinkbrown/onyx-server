// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! S2S session migration — the capsule a node ships to a peer to hand off a live
//! client session, plus the receiving node's holding area.
//!
//! Unlike a hot UPGRADE (same machine, the socket fd is inherited), an S2S
//! migration crosses processes/machines: the fd CANNOT move, so the client
//! reconnects to the target node and RECLAIMS its session by token. This module
//! is the data layer for that:
//!
//!   * `Capsule` — token + account + a `session_snapshot` blob (nick/account/
//!     hosts/away/oper/channels). The `fd` inside the snapshot is meaningless
//!     across machines and ignored on reclaim.
//!   * `PendingMigrations` — the target node's holding area: token -> (account,
//!     snapshot), inserted when the capsule arrives and consumed when the client
//!     reconnects with that token. Pairs with `sessions.SessionStore` (which
//!     tracks the reclaimable detached session) — this holds the state to restore.
//!
//! Transport-agnostic: the capsule rides whatever carries it (S2S relay frame,
//! conduit, ...). Wiring it onto the live S2S link + the reclaim path are later
//! slices.
const std = @import("std");

pub const Token = [16]u8;
pub const Error = error{ Truncated, TooLong };

/// A migrated session in flight: who it is + its serialized state.
pub const Capsule = struct {
    token: Token,
    account: []const u8,
    /// A `session_snapshot.encode` blob (borrowed on decode).
    snapshot: []const u8,
};

/// Wire: [16 token][u16 account_len][account][u32 snap_len][snapshot]
pub fn encode(allocator: std.mem.Allocator, cap: Capsule) (Error || std.mem.Allocator.Error)![]u8 {
    if (cap.account.len > std.math.maxInt(u16)) return error.TooLong;
    if (cap.snapshot.len > std.math.maxInt(u32)) return error.TooLong;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, &cap.token);
    var alen: [2]u8 = undefined;
    std.mem.writeInt(u16, &alen, @intCast(cap.account.len), .little);
    try out.appendSlice(allocator, &alen);
    try out.appendSlice(allocator, cap.account);
    var slen: [4]u8 = undefined;
    std.mem.writeInt(u32, &slen, @intCast(cap.snapshot.len), .little);
    try out.appendSlice(allocator, &slen);
    try out.appendSlice(allocator, cap.snapshot);
    return out.toOwnedSlice(allocator);
}

/// Decode a capsule, returning views that borrow `bytes`.
pub fn decode(bytes: []const u8) Error!Capsule {
    if (bytes.len < 16 + 2) return error.Truncated;
    var token: Token = undefined;
    @memcpy(&token, bytes[0..16]);
    var pos: usize = 16;
    const alen = std.mem.readInt(u16, bytes[pos..][0..2], .little);
    pos += 2;
    if (pos + alen + 4 > bytes.len) return error.Truncated;
    const account = bytes[pos .. pos + alen];
    pos += alen;
    const slen = std.mem.readInt(u32, bytes[pos..][0..4], .little);
    pos += 4;
    if (pos + slen > bytes.len) return error.Truncated;
    const snapshot = bytes[pos .. pos + slen];
    return .{ .token = token, .account = account, .snapshot = snapshot };
}

/// Target-node holding area: migrated sessions awaiting the client's reconnect.
/// Bounded two ways — a hard entry cap enforced in `put` and a TTL enforced by
/// the server's periodic `sweep` — so a signed-but-hostile (or buggy) peer
/// streaming capsules can never grow this map without bound.
pub const PendingMigrations = struct {
    allocator: std.mem.Allocator,
    map: std.AutoHashMapUnmanaged(Token, Entry) = .empty,

    /// Hard ceiling on staged entries. A staged entry is one detached session
    /// awaiting a reconnect; even a large mesh stages far fewer than this. On a
    /// full map `put` fails closed (the client's reclaim then falls back to the
    /// legacy redirect path) rather than evicting a legitimate pending entry.
    pub const max_entries: usize = 4096;

    pub const PutError = error{PendingFull} || std.mem.Allocator.Error;

    pub const Entry = struct {
        account: []u8,
        snapshot: []u8,
        /// Monotonic-ms staging time; `sweep` evicts entries older than the TTL.
        staged_at_ms: i64,
    };

    pub fn init(allocator: std.mem.Allocator) PendingMigrations {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *PendingMigrations) void {
        var it = self.map.valueIterator();
        while (it.next()) |e| {
            self.allocator.free(e.account);
            self.allocator.free(e.snapshot);
        }
        self.map.deinit(self.allocator);
    }

    /// Store a freshly-arrived capsule (copies the account + snapshot), stamped
    /// `now_ms` for TTL eviction. Replaces any existing entry for the same token
    /// (freeing the old). Fails closed with `PendingFull` when inserting a NEW
    /// token into a map already at `max_entries` (a replacement always succeeds).
    pub fn put(self: *PendingMigrations, cap: Capsule, now_ms: i64) PutError!void {
        if (self.map.count() >= max_entries and !self.map.contains(cap.token)) {
            return error.PendingFull;
        }
        const account = try self.allocator.dupe(u8, cap.account);
        errdefer self.allocator.free(account);
        const snapshot = try self.allocator.dupe(u8, cap.snapshot);
        errdefer self.allocator.free(snapshot);
        const gop = try self.map.getOrPut(self.allocator, cap.token);
        if (gop.found_existing) {
            self.allocator.free(gop.value_ptr.account);
            self.allocator.free(gop.value_ptr.snapshot);
        }
        gop.value_ptr.* = .{ .account = account, .snapshot = snapshot, .staged_at_ms = now_ms };
    }

    /// Evict every entry staged at least `ttl_ms` before `now_ms` (freeing its
    /// copies). Returns the count evicted. Best-effort: if the scratch key list
    /// cannot be allocated nothing is evicted this round — the next sweep
    /// retries. Called periodically by the server (reactor 0's timer tick).
    pub fn sweep(self: *PendingMigrations, now_ms: i64, ttl_ms: u64) usize {
        var expired: std.ArrayList(Token) = .empty;
        defer expired.deinit(self.allocator);
        var it = self.map.iterator();
        while (it.next()) |e| {
            const age = now_ms -| e.value_ptr.staged_at_ms;
            if (age >= 0 and @as(u64, @intCast(age)) >= ttl_ms) {
                expired.append(self.allocator, e.key_ptr.*) catch return 0;
            }
        }
        for (expired.items) |token| {
            const kv = self.map.fetchRemove(token) orelse continue;
            self.allocator.free(kv.value.account);
            self.allocator.free(kv.value.snapshot);
        }
        return expired.items.len;
    }

    /// Whether a migrated session is waiting for `token`.
    pub fn has(self: *const PendingMigrations, token: Token) bool {
        return self.map.contains(token);
    }

    /// Remove and return the migrated session for `token` (caller owns the slices;
    /// release with `freeEntry`). Null if none — the client reclaims on reconnect.
    pub fn take(self: *PendingMigrations, token: Token) ?Entry {
        const e = self.map.fetchRemove(token) orelse return null;
        return e.value;
    }

    pub fn freeEntry(self: *PendingMigrations, e: Entry) void {
        self.allocator.free(e.account);
        self.allocator.free(e.snapshot);
    }

    pub fn count(self: *const PendingMigrations) usize {
        return self.map.count();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const migration_relay = @import("migration_relay.zig");

test "migration capsule encode/decode round-trips" {
    const allocator = testing.allocator;
    const token: Token = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const cap = Capsule{ .token = token, .account = "alice", .snapshot = "snap-bytes-here" };
    const bytes = try encode(allocator, cap);
    defer allocator.free(bytes);

    const got = try decode(bytes);
    try testing.expectEqualSlices(u8, &token, &got.token);
    try testing.expectEqualStrings("alice", got.account);
    try testing.expectEqualStrings("snap-bytes-here", got.snapshot);
}

test "decode rejects truncated input" {
    try testing.expectError(error.Truncated, decode(&[_]u8{ 1, 2, 3 }));
    // valid token + account-len claiming more than present
    var buf: [20]u8 = @splat(0);
    buf[16] = 50; // account_len = 50, but no bytes follow
    try testing.expectError(error.Truncated, decode(&buf));
}

test "PendingMigrations stores, finds, and consumes by token" {
    const allocator = testing.allocator;
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();

    const t1: Token = @as([15]u8, @splat(0)) ++ .{1};
    const t2: Token = @as([15]u8, @splat(0)) ++ .{2};
    try pm.put(.{ .token = t1, .account = "alice", .snapshot = "A" }, 1000);
    try pm.put(.{ .token = t2, .account = "bob", .snapshot = "BB" }, 1000);
    try testing.expectEqual(@as(usize, 2), pm.count());
    try testing.expect(pm.has(t1));

    const e = pm.take(t1) orelse return error.TestUnexpectedResult;
    defer pm.freeEntry(e);
    try testing.expectEqualStrings("alice", e.account);
    try testing.expectEqualStrings("A", e.snapshot);
    try testing.expect(!pm.has(t1)); // consumed
    try testing.expect(pm.take(t1) == null);
    try testing.expectEqual(@as(usize, 1), pm.count()); // bob remains
}

test "put replaces an existing token without leaking" {
    const allocator = testing.allocator;
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();
    const t: Token = @splat(9);
    try pm.put(.{ .token = t, .account = "old", .snapshot = "x" }, 1000);
    try pm.put(.{ .token = t, .account = "new", .snapshot = "yy" }, 1000);
    try testing.expectEqual(@as(usize, 1), pm.count());
    const e = pm.take(t).?;
    defer pm.freeEntry(e);
    try testing.expectEqualStrings("new", e.account);
}

test "put fails closed at max_entries; a replacement of an existing token still succeeds" {
    const allocator = testing.allocator;
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();

    // Fill to the cap (distinct tokens derived from the loop index).
    var i: usize = 0;
    while (i < PendingMigrations.max_entries) : (i += 1) {
        var t: Token = @splat(0);
        std.mem.writeInt(u64, t[0..8], i, .little);
        try pm.put(.{ .token = t, .account = "acct", .snapshot = "s" }, 1);
    }
    try testing.expectEqual(PendingMigrations.max_entries, pm.count());

    // A NEW token is rejected — the map never grows past the cap.
    const fresh: Token = @splat(0xFF);
    try testing.expectError(
        error.PendingFull,
        pm.put(.{ .token = fresh, .account = "evil", .snapshot = "x" }, 2),
    );
    try testing.expectEqual(PendingMigrations.max_entries, pm.count());
    try testing.expect(!pm.has(fresh));

    // Replacing an EXISTING token at the cap succeeds (count unchanged).
    const t0: Token = @splat(0);
    try pm.put(.{ .token = t0, .account = "replaced", .snapshot = "zz" }, 3);
    try testing.expectEqual(PendingMigrations.max_entries, pm.count());
    const e = pm.take(t0).?;
    defer pm.freeEntry(e);
    try testing.expectEqualStrings("replaced", e.account);

    // Consuming an entry frees a slot; a new token is admitted again.
    try pm.put(.{ .token = fresh, .account = "ok", .snapshot = "y" }, 4);
    try testing.expect(pm.has(fresh));
}

test "sweep evicts entries past the TTL and keeps fresh ones" {
    const allocator = testing.allocator;
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();

    const stale: Token = @as([15]u8, @splat(0)) ++ .{1};
    const fresh: Token = @as([15]u8, @splat(0)) ++ .{2};
    try pm.put(.{ .token = stale, .account = "old", .snapshot = "a" }, 1_000);
    try pm.put(.{ .token = fresh, .account = "new", .snapshot = "b" }, 9_000);

    // Nothing lapsed yet: age(stale)=4000 < ttl.
    try testing.expectEqual(@as(usize, 0), pm.sweep(5_000, 5_000));
    try testing.expectEqual(@as(usize, 2), pm.count());

    // stale's age hits the TTL exactly (>= evicts); fresh survives.
    try testing.expectEqual(@as(usize, 1), pm.sweep(6_000, 5_000));
    try testing.expect(!pm.has(stale));
    try testing.expect(pm.has(fresh));

    // A re-staged token's clock restarts from its new staged_at.
    try pm.put(.{ .token = stale, .account = "old2", .snapshot = "c" }, 10_000);
    try testing.expectEqual(@as(usize, 0), pm.sweep(11_000, 5_000));
    try testing.expect(pm.has(stale));
}

test "end-to-end: origin prepare -> session_migrate wrap -> target accept -> PendingMigrations -> reclaim consume" {
    // Exercises exactly the server seam: the origin mints a signed migration
    // capsule, wraps it in a session_migrate.Capsule keyed by the 16-byte session
    // token, the target verifies it (MigrationTarget.accept) and stages it under
    // that key, then a reclaim by the matching token takes + decodes the full
    // restored snapshot (nick/umodes/channels/away/account/host/is_oper).
    const allocator = testing.allocator;
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x7E)));

    // ORIGIN: build the full session snapshot and mint the relay frame.
    const channels = [_][]const u8{ "#orochi", "#helix", "#ops" };
    const snapshot = migration_relay.Snapshot{
        .nick = "kain",
        .umodes = "+iwx",
        .channels = channels[0..],
        .realname = "Kain Example",
        .host = "cloak-ab12.orochi",
        .account = "kain",
        .away = "migrating",
        .is_oper = true,
    };
    var origin = migration_relay.MigrationOrigin.init(allocator, kp);
    defer origin.deinit();
    var prepared = try origin.prepare("kain", snapshot, 0xCAFEBABE, 7);
    defer prepared.deinit(allocator);

    // ORIGIN: wrap the relay frame in a session_migrate capsule keyed by the
    // 16-byte session token (the reclaim-side lookup key) and serialize for S2S.
    const session_token: Token = .{ 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    const wire = try encode(allocator, .{
        .token = session_token,
        .account = "kain",
        .snapshot = prepared.frame_bytes,
    });
    defer allocator.free(wire);

    // TARGET: decode the outer capsule, verify+decode the relay frame, then stage
    // the re-encoded snapshot under the session-token key.
    const outer = try decode(wire);
    try testing.expectEqualSlices(u8, &session_token, &outer.token);

    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();
    {
        var target = migration_relay.MigrationTarget.init(allocator, kp.public_key.toBytes());
        defer target.deinit();
        var capsule = try target.accept(outer.snapshot);
        defer capsule.deinit(allocator);
        try testing.expectEqualStrings("kain", capsule.account);

        const snap_bytes = try capsule.snapshot.encode(allocator);
        defer allocator.free(snap_bytes);
        try pm.put(.{ .token = outer.token, .account = outer.account, .snapshot = snap_bytes }, 1000);
    }
    try testing.expect(pm.has(session_token));

    // RECLAIM: the client reconnects + presents the matching token; consume.
    const entry = pm.take(session_token) orelse return error.TestUnexpectedResult;
    defer pm.freeEntry(entry);
    try testing.expectEqualStrings("kain", entry.account);
    try testing.expect(!pm.has(session_token)); // consumed

    var restored = try migration_relay.Snapshot.decode(allocator, entry.snapshot);
    defer restored.deinit(allocator);
    try testing.expectEqualStrings("kain", restored.nick);
    try testing.expectEqualStrings("+iwx", restored.umodes);
    try testing.expectEqual(@as(usize, 3), restored.channels.len);
    try testing.expectEqualStrings("#orochi", restored.channels[0]);
    try testing.expectEqualStrings("#ops", restored.channels[2]);
    try testing.expectEqualStrings("Kain Example", restored.realname);
    try testing.expectEqualStrings("cloak-ab12.orochi", restored.host);
    try testing.expectEqualStrings("kain", restored.account);
    try testing.expectEqualStrings("migrating", restored.away);
    try testing.expect(restored.is_oper);
}

test "end-to-end: target rejects a capsule signed by the wrong key (no staging)" {
    const allocator = testing.allocator;
    const Ed25519 = std.crypto.sign.Ed25519;
    const real = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x01)));
    const attacker = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x02)));

    const channels = [_][]const u8{"#orochi"};
    const snapshot = migration_relay.Snapshot{ .nick = "kain", .umodes = "+i", .channels = channels[0..] };
    var origin = migration_relay.MigrationOrigin.init(allocator, attacker); // signs with attacker key
    defer origin.deinit();
    var prepared = try origin.prepare("kain", snapshot, 0x1, 1);
    defer prepared.deinit(allocator);

    const session_token: Token = @splat(1);
    const wire = try encode(allocator, .{ .token = session_token, .account = "kain", .snapshot = prepared.frame_bytes });
    defer allocator.free(wire);
    const outer = try decode(wire);

    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();
    var target = migration_relay.MigrationTarget.init(allocator, real.public_key.toBytes()); // pins the REAL key
    defer target.deinit();
    // Verification fails: nothing is staged.
    try testing.expectError(error.BadSignature, target.accept(outer.snapshot));
    try testing.expect(!pm.has(session_token));
    try testing.expectEqual(@as(usize, 0), pm.count());
}

test "a staged entry rides a Helix .pending_migration capsule across USR2 (round-trip)" {
    // The seal side wraps each PendingMigrations entry as a session_migrate wire
    // blob inside a `.pending_migration` Helix capsule (ordinal 1, exactly how
    // helix_live.prepare frames every StatePiece); the adopt side decodes the
    // capsule field and re-stages it. Prove the full byte path round-trips.
    const allocator = testing.allocator;
    const helix_capsule = @import("capsule.zig");

    const token: Token = @as([15]u8, @splat(7)) ++ .{1};
    const wire = try encode(allocator, .{ .token = token, .account = "kain", .snapshot = "verified-snapshot-bytes" });
    defer allocator.free(wire);

    var fields = [_]helix_capsule.Field{.{ .ordinal = 1, .bytes = wire }};
    const sealed = try helix_capsule.encode(allocator, helix_capsule.make(.pending_migration, fields[0..]));
    defer allocator.free(sealed);

    var adopted = try helix_capsule.decode(allocator, sealed);
    defer adopted.deinit(allocator);
    try testing.expectEqual(helix_capsule.CapsuleKind.pending_migration, adopted.header.kind);
    try testing.expectEqual(@as(u16, 1), adopted.header.version);
    try testing.expectEqual(@as(usize, 1), adopted.fields.len);

    const got = try decode(adopted.fields[0].bytes);
    try testing.expectEqualSlices(u8, &token, &got.token);
    try testing.expectEqualStrings("kain", got.account);
    try testing.expectEqualStrings("verified-snapshot-bytes", got.snapshot);

    // Re-staging on the successor works and is consumable by token.
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();
    try pm.put(got, 42);
    try testing.expect(pm.has(token));
}

test "adopting a truncated .pending_migration payload fails closed (tolerant decode)" {
    // A corrupt inner blob must be a clean skip on the successor, never a crash
    // and never a partially-staged entry.
    const allocator = testing.allocator;
    const token: Token = @splat(3);
    const wire = try encode(allocator, .{ .token = token, .account = "kain", .snapshot = "snapshot" });
    defer allocator.free(wire);

    // Truncate mid-snapshot and mid-header: both reject with Truncated.
    try testing.expectError(error.Truncated, decode(wire[0 .. wire.len - 3]));
    try testing.expectError(error.Truncated, decode(wire[0..10]));
}
