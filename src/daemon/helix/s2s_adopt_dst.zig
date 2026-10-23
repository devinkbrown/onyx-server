// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic-Ocean coverage for the Helix `.s2s_link` capsule adoption path
//! at the CAPSULE-STREAM level — the exact old→new UPGRADEs that the v2 bump (adding
//! `admitted_frame_families` to `Established`, growing the embedded blob by 4 bytes),
//! the v3 bump (adding `caps_ext`, growing the blob by one byte), and the v4 bump
//! (appending the converged remote-member roster block) must survive without
//! a netsplit. "Upgrades are where panics live," so this
//! models the successor's `adoptInheritedSessions` loop (server.zig, Pass 0 + Pass 4)
//! and asserts the invariant that matters: every inherited s2s socket fd is
//! ACCOUNTED FOR — adopted onto a live link or recovered+closed on a clean drop —
//! never leaked, and sibling capsules keep adopting regardless.
//!
//! This is a TEST-ONLY faithful model of `LinuxServer.adoptInheritedSessions`
//! (src/daemon/server.zig ~16566): the real loop needs a bound reactor, an inherited
//! memfd arena, and live sockets, none of which belong in a deterministic unit test.
//! The model drives the REAL production decoders — `capsule.decodeStream` (the arena
//! walk `helix_live.readArena` performs), `s2s_snapshot.decode`, and
//! `s2s_snapshot.peekFd` (the fd-recovery seam) — and injects faults with
//! `fault_loom` at the model's decode site, standing in for the production decode
//! that has no fault site of its own. The fd ledger stands in for the kernel fd
//! table; a non-empty ledger after adoption is exactly an fd leak.

const std = @import("std");

const capsule = @import("capsule.zig");
const s2s_snapshot = @import("s2s_snapshot.zig");
const ticket_key_capsule = @import("ticket_key_capsule.zig");
const fault_loom = @import("../../substrate/fault_loom.zig");

const Allocator = std.mem.Allocator;
const testing = std.testing;

/// Byte offset of the embedded `Established` region inside a snapshot blob:
/// `fd`(i32) + `role`(u8) + `s2s_initiator`(u8). The v2-only trailing
/// `admitted_frame_families`(u32) lives at the END of that region — a v1 blob is
/// a v2 blob minus exactly those 4 bytes.
const est_field_off: usize = @sizeOf(i32) + 1 + 1;

/// Byte offset of the v3-only `caps_ext` field. Keep this written in terms of the
/// preceding wire fields so a future layout change cannot silently make the
/// predecessor fixtures exercise the current layout under an old header.
const caps_ext_field_off_v2: usize = est_field_off + s2s_snapshot.est_len +
    8 + 8 + 8 +
    8 + 8 + 4 + 4 + 8 + 8 + 8 +
    8 + 8 + 1;

/// A synthetic-but-structurally-valid snapshot for the link on `fd`. The
/// `established` region gets a recognizable, fd-derived pattern and a NON-ZERO
/// trailing `admitted_frame_families` so a v1 splice/decode is observable.
fn sampleSnap(fd: i32) s2s_snapshot.Snapshot {
    var snap = s2s_snapshot.Snapshot{
        .fd = fd,
        .role = 1,
        .s2s_initiator = true,
        .send_counter = 0x1111_2222_3333_4444,
        .recv_counter = 0x5555_6666_7777_8888,
        .feed_seq = 99,
        .pl_send_credit = 60000,
        .pl_next_out_seq = 7,
        .pl_next_in_seq = 6,
        .caps = s2s_snapshot.cap_signing | s2s_snapshot.cap_repair,
        .remote_name = "peer.example",
        .rec_inbuf = "half",
        .pending_out = "queued",
    };
    const fd_u: u8 = @truncate(@as(u32, @bitCast(fd)));
    for (&snap.established, 0..) |*b, i| b.* = @truncate(i * 7 + fd_u + 1);
    std.mem.writeInt(u32, snap.established[s2s_snapshot.est_len - 4 ..][0..4], 0xABCD_1234, .little);
    return snap;
}

/// Synthesize the pre-roster (v3-layout) wire image from a current-encode blob
/// by stripping the empty v5 carry and v4 roster blocks. Valid only when both
/// were EMPTY (12 zero bytes: count=0, len=0, inner_len=0) —
/// every pre-v4 fixture here models a rosterless predecessor.
fn stripEmptyRosterBlock(allocator: Allocator, current_blob: []const u8) ![]u8 {
    std.debug.assert(current_blob.len >= 12);
    for (current_blob[current_blob.len - 12 ..]) |b| std.debug.assert(b == 0);
    return allocator.dupe(u8, current_blob[0 .. current_blob.len - 12]);
}

/// Encode an actual schema-v3 `.s2s_link` capsule — the immediately-prior
/// PRODUCTION schema (what the currently-deployed binary seals). The current
/// encoder writes v4, so strip the trailing roster block and advertise the
/// exact v3 range. Caller owns the returned bytes.
fn v3Capsule(allocator: Allocator, snap: s2s_snapshot.Snapshot) ![]u8 {
    const current_blob = try s2s_snapshot.encode(allocator, snap);
    defer allocator.free(current_blob);
    const v3_blob = try stripEmptyRosterBlock(allocator, current_blob);
    defer allocator.free(v3_blob);

    const d = capsule.descriptor(.s2s_link);
    const v3_header = capsule.Header{
        .schema_id = d.schema_id,
        .kind = .s2s_link,
        .version = 3,
        .min_supported = 1,
        .max_supported = 3,
    };
    var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = v3_blob }};
    return capsule.encode(allocator, .{ .header = v3_header, .fields = fields[0..] });
}

/// Encode an actual schema-v2 `.s2s_link` capsule. The current encoder writes v4,
/// so strip the v4-only roster block, remove the v3-only `caps_ext` byte, and
/// advertise the exact v2 range. Caller owns the returned bytes.
fn v2Capsule(allocator: Allocator, snap: s2s_snapshot.Snapshot) ![]u8 {
    const current_blob = try s2s_snapshot.encode(allocator, snap);
    defer allocator.free(current_blob);
    const v3_blob = try stripEmptyRosterBlock(allocator, current_blob);
    defer allocator.free(v3_blob);

    const v2_blob = try allocator.alloc(u8, v3_blob.len - 1);
    defer allocator.free(v2_blob);
    @memcpy(v2_blob[0..caps_ext_field_off_v2], v3_blob[0..caps_ext_field_off_v2]);
    @memcpy(v2_blob[caps_ext_field_off_v2..], v3_blob[caps_ext_field_off_v2 + 1 ..]);

    const d = capsule.descriptor(.s2s_link);
    const v2_header = capsule.Header{
        .schema_id = d.schema_id,
        .kind = .s2s_link,
        .version = 2,
        .min_supported = 1,
        .max_supported = 2,
    };
    var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = v2_blob }};
    return capsule.encode(allocator, .{ .header = v2_header, .fields = fields[0..] });
}

/// Encode a v1 `.s2s_link` capsule as a PRE-BUMP binary would have sealed it: the
/// embedded `Established` blob is 4 bytes shorter (no `admitted_frame_families`)
/// and the capsule header advertises `version=1, min=1, max=1`. Built by encoding
/// the current blob and removing every later addition — v4's roster block, v3's
/// `caps_ext` byte, and v2's trailing Established u32 — then wrapping in a
/// hand-crafted v1 header the current binary still accepts (`min_supported = 1`).
fn v1Capsule(allocator: Allocator, snap: s2s_snapshot.Snapshot) ![]u8 {
    const current_blob = try s2s_snapshot.encode(allocator, snap);
    defer allocator.free(current_blob);
    const v3_blob = try stripEmptyRosterBlock(allocator, current_blob);
    defer allocator.free(v3_blob);

    const v2_blob = try allocator.alloc(u8, v3_blob.len - 1);
    defer allocator.free(v2_blob);
    @memcpy(v2_blob[0..caps_ext_field_off_v2], v3_blob[0..caps_ext_field_off_v2]);
    @memcpy(v2_blob[caps_ext_field_off_v2..], v3_blob[caps_ext_field_off_v2 + 1 ..]);

    const cut_at = est_field_off + s2s_snapshot.est_len - 4;
    var v1_blob: std.ArrayList(u8) = .empty;
    defer v1_blob.deinit(allocator);
    try v1_blob.appendSlice(allocator, v2_blob[0..cut_at]);
    try v1_blob.appendSlice(allocator, v2_blob[cut_at + 4 ..]);
    std.debug.assert(v1_blob.items.len == v2_blob.len - 4);

    const d = capsule.descriptor(.s2s_link);
    const v1_header = capsule.Header{
        .schema_id = d.schema_id,
        .kind = .s2s_link,
        .version = 1,
        .min_supported = 1,
        .max_supported = 1,
    };
    var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = v1_blob.items }};
    return capsule.encode(allocator, .{ .header = v1_header, .fields = fields[0..] });
}

/// Encode a FORWARD-VERSIONED (too-new) `.s2s_link` capsule: a hypothetical future
/// binary sealed it at `schema_version + 1`. The current capsule layer
/// forward-accepts it (the advertised range overlaps the local `[1,4]` range), so the
/// blob survives the stream walk and reaches `s2s_snapshot.decode`, which then
/// rejects the unknown version fail-closed — the fd must still be recovered.
fn tooNewCapsule(allocator: Allocator, snap: s2s_snapshot.Snapshot) ![]u8 {
    const blob = try s2s_snapshot.encode(allocator, snap);
    defer allocator.free(blob);
    const d = capsule.descriptor(.s2s_link);
    const future_header = capsule.Header{
        .schema_id = d.schema_id,
        .kind = .s2s_link,
        .version = s2s_snapshot.schema_version + 1,
        .min_supported = 1,
        .max_supported = s2s_snapshot.schema_version + 1,
    };
    var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = blob }};
    return capsule.encode(allocator, .{ .header = future_header, .fields = fields[0..] });
}

/// A `.s2s_link` capsule whose embedded blob is deliberately truncated (a corrupt
/// or partially-written inherited blob). The capsule layer stores the short bytes
/// verbatim; `s2s_snapshot.decode` then fails `Truncated`. `fd_bytes` seeds the
/// leading i32 so `peekFd` can still recover the fd for cleanup.
fn truncatedS2sCapsule(allocator: Allocator, version: u16, fd: i32) ![]u8 {
    var short: [10]u8 = @splat(0);
    std.mem.writeInt(i32, short[0..4], fd, .little);
    const d = capsule.descriptor(.s2s_link);
    const header = capsule.Header{
        .schema_id = d.schema_id,
        .kind = .s2s_link,
        .version = version,
        .min_supported = 1,
        .max_supported = 2,
    };
    var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = &short }};
    return capsule.encode(allocator, .{ .header = header, .fields = fields[0..] });
}

/// A sibling (non-s2s) capsule — a TLS ticket-key capsule (the real Pass-0 kind).
/// Used purely as a generic "an unrelated capsule still adopts" marker to prove
/// sibling passes are UNAFFECTED by any s2s outcome. NOTE: the real Pass 0
/// (server.zig ~16475) is a singleton that `break`s after the first ticket-key
/// capsule; the model counts each one so a stream can carry several sibling
/// markers, which is why tests may assert `siblings_adopted > 1`.
fn ticketKeyCapsule(allocator: Allocator, fill: u8) ![]u8 {
    const key_len = @typeInfo(@FieldType(ticket_key_capsule.Snapshot, "current")).array.len;
    const cur: [key_len]u8 = @splat(fill);
    const blob = try ticket_key_capsule.encode(allocator, .{ .current = cur });
    defer allocator.free(blob);
    var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = blob }};
    return capsule.encode(allocator, capsule.make(.tls_ticket_keys, fields[0..]));
}

/// Per-link fault site so a single seeded campaign produces a genuinely MIXED
/// intra-run interleaving (some links dropped, others adopted) rather than a
/// uniform all-or-nothing decision — `fault_loom` campaigns hash `(seed, site)`
/// with no per-hit counter, so the site MUST vary per link. Keyed by the link's
/// stable inherited fd, which both `adoptStream` and the arming tests recover via
/// `peekFd`, so their site strings always agree.
fn s2sDecodeSite(buf: []u8, fd: i32) []const u8 {
    return std.fmt.bufPrint(buf, "s2s.decode.{d}", .{fd}) catch "s2s.decode";
}

const AdoptResult = struct {
    siblings_adopted: usize = 0,
    s2s_adopted: usize = 0,
    s2s_dropped: usize = 0,
    fds_recovered: usize = 0,
    /// fds still open after adoption — anything > 0 is an fd LEAK (the bug this
    /// whole path exists to prevent).
    fds_leaked: usize = 0,
};

/// A faithful model of `LinuxServer.adoptInheritedSessions` restricted to the
/// sibling (Pass 0) + `.s2s_link` (Pass 4) handling. `loom`, when non-null, may fail
/// the model's `"s2s.decode"` site to force the recovery branch — standing in for a
/// production decode fault. `open` is the modeled kernel fd table for inherited s2s
/// sockets; on return every inherited fd must be gone from it.
fn adoptStream(
    allocator: Allocator,
    stream: []const u8,
    loom: ?*fault_loom.Registry,
    open: *std.AutoHashMapUnmanaged(i32, void),
) !AdoptResult {
    var res = AdoptResult{};

    // The real arena walk. A malformed stream fails here fail-closed (whole resume
    // aborts) — that is itself a clean, no-panic outcome.
    const caps = try capsule.decodeStream(allocator, stream);
    defer {
        for (caps) |*c| c.deinit(allocator);
        allocator.free(caps);
    }

    // Seed the fd ledger from every carried s2s link (models the inherited sockets
    // whose fds survived execve and now MUST be accounted for).
    for (caps) |c| {
        if (c.header.kind != .s2s_link) continue;
        if (c.fields.len == 0) continue;
        if (s2s_snapshot.peekFd(c.fields[0].bytes)) |fd| {
            if (fd >= 0) try open.put(allocator, fd, {});
        }
    }

    // Pass 0 model: sibling adoption (TLS ticket keys). Independent of s2s outcome.
    for (caps) |c| {
        if (c.header.kind != .tls_ticket_keys) continue;
        if (c.fields.len == 0) continue;
        _ = ticket_key_capsule.decode(c.fields[0].bytes) catch continue;
        res.siblings_adopted += 1;
    }

    // Pass 4 model: preserved secured-link re-attach, mirroring server.zig ~16566.
    for (caps) |c| {
        if (c.header.kind != .s2s_link) continue;
        if (c.fields.len == 0) continue;

        const decoded: ?s2s_snapshot.Snapshot = decode_blk: {
            if (loom) |l| {
                var site_buf: [32]u8 = undefined;
                const cap_fd = s2s_snapshot.peekFd(c.fields[0].bytes) orelse -1;
                const site = s2sDecodeSite(&site_buf, cap_fd);
                l.maybeFail(site, error{Injected}) catch break :decode_blk null;
            }
            break :decode_blk s2s_snapshot.decode(c.fields[0].bytes, c.header.version) catch null;
        };

        if (decoded) |snap| {
            if (snap.fd < 0) continue;
            // Adopted: the fd is handed to a live link (kept open, but ACCOUNTED).
            _ = open.remove(snap.fd);
            res.s2s_adopted += 1;
        } else {
            // Clean drop: recover the fd from the fixed leading field and close it,
            // so a decode failure never leaks the inherited socket.
            res.s2s_dropped += 1;
            if (s2s_snapshot.peekFd(c.fields[0].bytes)) |fd| {
                if (fd >= 0 and open.remove(fd)) res.fds_recovered += 1;
            }
        }
    }

    res.fds_leaked = open.count();
    return res;
}

/// Concatenate owned capsule buffers into one arena-format stream, freeing each.
fn joinCaps(allocator: Allocator, parts: []const []u8) ![]u8 {
    var stream: std.ArrayList(u8) = .empty;
    errdefer stream.deinit(allocator);
    for (parts) |p| {
        try stream.appendSlice(allocator, p);
        allocator.free(p);
    }
    return stream.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "s2s_link v1 capsule adopts across upgrade while sibling capsules still adopt" {
    const allocator = testing.allocator;

    // Mixed stream mirroring a real old→new arena: sibling, a v1 s2s link (as the
    // pre-bump binary sealed it), and a second sibling. Order is intentionally
    // interleaved to prove the s2s handling does not perturb sibling passes.
    const parts = [_][]u8{
        try ticketKeyCapsule(allocator, 0xA1),
        try v1Capsule(allocator, sampleSnap(41)),
        try ticketKeyCapsule(allocator, 0xB2),
    };
    const stream = try joinCaps(allocator, parts[0..]);
    defer allocator.free(stream);

    var open: std.AutoHashMapUnmanaged(i32, void) = .empty;
    defer open.deinit(allocator);

    const res = try adoptStream(allocator, stream, null, &open);

    // Both siblings adopt; the v1 link is adopted via the legacy decode arm (the
    // whole point of `min_supported = 1`), and no fd leaks.
    try testing.expectEqual(@as(usize, 2), res.siblings_adopted);
    try testing.expectEqual(@as(usize, 1), res.s2s_adopted);
    try testing.expectEqual(@as(usize, 0), res.s2s_dropped);
    try testing.expectEqual(@as(usize, 0), res.fds_leaked);
}

test "s2s_link v1 and v2 capsules co-adopt in one upgrade stream, fd ledger balanced" {
    const allocator = testing.allocator;

    // A heterogeneous fleet: a preserved v1 link (pre-bump peer) and a v2 link
    // (post-bump peer) carried together — the exact mid-fleet upgrade state.
    const parts = [_][]u8{
        try v1Capsule(allocator, sampleSnap(50)),
        try ticketKeyCapsule(allocator, 0xC3),
        try v2Capsule(allocator, sampleSnap(51)),
    };
    const stream = try joinCaps(allocator, parts[0..]);
    defer allocator.free(stream);

    var open: std.AutoHashMapUnmanaged(i32, void) = .empty;
    defer open.deinit(allocator);

    const res = try adoptStream(allocator, stream, null, &open);
    try testing.expectEqual(@as(usize, 1), res.siblings_adopted);
    try testing.expectEqual(@as(usize, 2), res.s2s_adopted);
    try testing.expectEqual(@as(usize, 0), res.s2s_dropped);
    try testing.expectEqual(@as(usize, 0), res.fds_leaked);
}

/// Encode a CURRENT (v4) `.s2s_link` capsule carrying `snap` verbatim —
/// including any roster block. Caller owns the returned bytes.
fn currentCapsule(allocator: Allocator, snap: s2s_snapshot.Snapshot) ![]u8 {
    const blob = try s2s_snapshot.encode(allocator, snap);
    defer allocator.free(blob);
    var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = blob }};
    return capsule.encode(allocator, capsule.make(.s2s_link, fields[0..]));
}

test "s2s_link v3 capsule (previous production schema) co-adopts with a v4 roster capsule across upgrade" {
    const allocator = testing.allocator;

    // The exact next-deploy stream: a v3 link sealed by the currently-deployed
    // binary rides beside a v4 link whose blob carries a converged roster.
    var roster: std.ArrayList(u8) = .empty;
    defer roster.deinit(allocator);
    try s2s_snapshot.appendRosterMember(allocator, &roster, .{
        .channel = "#root",
        .nick = "trev",
        .node = 0xB0B,
        .status = 2,
        .hlc = 700,
        .username = "trev",
        .host = "cloak.ircx.us",
    });
    var v4_snap = sampleSnap(55);
    v4_snap.roster = roster.items;
    v4_snap.roster_count = 1;

    const parts = [_][]u8{
        try v3Capsule(allocator, sampleSnap(54)),
        try ticketKeyCapsule(allocator, 0x3C),
        try currentCapsule(allocator, v4_snap),
    };
    const stream = try joinCaps(allocator, parts[0..]);
    defer allocator.free(stream);

    var open: std.AutoHashMapUnmanaged(i32, void) = .empty;
    defer open.deinit(allocator);

    const res = try adoptStream(allocator, stream, null, &open);
    try testing.expectEqual(@as(usize, 1), res.siblings_adopted);
    try testing.expectEqual(@as(usize, 2), res.s2s_adopted);
    try testing.expectEqual(@as(usize, 0), res.s2s_dropped);
    try testing.expectEqual(@as(usize, 0), res.fds_leaked);
}

test "s2s_link v4 capsule with a corrupt roster is refused fail-closed and fd recovered on resume" {
    const allocator = testing.allocator;

    var roster: std.ArrayList(u8) = .empty;
    defer roster.deinit(allocator);
    try s2s_snapshot.appendRosterMember(allocator, &roster, .{
        .channel = "#root",
        .nick = "trev",
        .node = 0xB0B,
        .status = 2,
        .hlc = 700,
    });
    var snap = sampleSnap(56);
    snap.roster = roster.items;
    snap.roster_count = 1;
    const blob = try s2s_snapshot.encode(allocator, snap);
    defer allocator.free(blob);
    // Corrupt the roster block's declared count so the decode-time walk
    // mismatches — the link must drop cleanly, never adopt a partial roster.
    const count_off = blob.len - roster.items.len - 12;
    std.mem.writeInt(u32, blob[count_off..][0..4], 9, .little);
    var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = blob }};
    const bad = try capsule.encode(allocator, capsule.make(.s2s_link, fields[0..]));

    const parts = [_][]u8{
        bad,
        try ticketKeyCapsule(allocator, 0x4D),
    };
    const stream = try joinCaps(allocator, parts[0..]);
    defer allocator.free(stream);

    var open: std.AutoHashMapUnmanaged(i32, void) = .empty;
    defer open.deinit(allocator);

    const res = try adoptStream(allocator, stream, null, &open);
    try testing.expectEqual(@as(usize, 1), res.siblings_adopted);
    try testing.expectEqual(@as(usize, 0), res.s2s_adopted);
    try testing.expectEqual(@as(usize, 1), res.s2s_dropped);
    try testing.expectEqual(@as(usize, 1), res.fds_recovered);
    try testing.expectEqual(@as(usize, 0), res.fds_leaked);
}

test "s2s_link capsule adoption recovers fd under injected decode fault (resume DST)" {
    const allocator = testing.allocator;

    var loom: fault_loom.Registry = .{};
    defer loom.deinit(allocator);
    // Knock out exactly the v1 link (inherited fd 61) at decode. Two links are
    // carried; the v2 link (fd 60) adopts, the v1 link's decode is forced to fail —
    // its fd must be recovered, not leaked, and the interleaved sibling must still
    // adopt. The site is keyed by fd, matching `adoptStream`'s per-link site.
    var site_buf: [32]u8 = undefined;
    try loom.arm(allocator, s2sDecodeSite(&site_buf, 61), 1, error.Injected);

    const parts = [_][]u8{
        try v2Capsule(allocator, sampleSnap(60)),
        try ticketKeyCapsule(allocator, 0xD4),
        try v1Capsule(allocator, sampleSnap(61)),
    };
    const stream = try joinCaps(allocator, parts[0..]);
    defer allocator.free(stream);

    var open: std.AutoHashMapUnmanaged(i32, void) = .empty;
    defer open.deinit(allocator);

    const res = try adoptStream(allocator, stream, &loom, &open);
    try testing.expectEqual(@as(usize, 1), res.siblings_adopted);
    try testing.expectEqual(@as(usize, 1), res.s2s_adopted);
    try testing.expectEqual(@as(usize, 1), res.s2s_dropped);
    try testing.expectEqual(@as(usize, 1), res.fds_recovered);
    try testing.expectEqual(@as(usize, 0), res.fds_leaked); // clean abort, no leak
}

test "s2s_link capsule adoption seeded fault campaign keeps fd ledger balanced" {
    const allocator = testing.allocator;

    // Sweep a spread of seeds. Because the fault site is keyed per link, a single
    // seed produces a genuinely MIXED interleaving — some of the three links drop
    // while others adopt — and under EVERY such interleaving the safety invariant
    // must hold: no fd leaks, siblings always adopt, every dropped link's fd is
    // recovered. On any failure the seed is printed so the exact case replays.
    const seeds = [_]u64{
        0x0000_0000_0000_0001,
        0xa11c_e5ee_d0d0_beef,
        0xdead_beef_cafe_f00d,
        0x1234_5678_9abc_def0,
        0xffff_ffff_ffff_ffff,
        0x5eed_5eed_5eed_5eed,
    };

    for (seeds) |seed| {
        runCampaign(allocator, seed) catch |e| {
            std.debug.print(
                "s2s_link adopt fault-campaign FAILED — replay with seed=0x{x:0>16}\n",
                .{seed},
            );
            return e;
        };
    }
}

fn runCampaign(allocator: Allocator, seed: u64) !void {
    var loom: fault_loom.Registry = .{};
    defer loom.deinit(allocator);
    loom.setCampaign(.{ .seed = seed, .one_in = 2, .err = error.Injected });

    const parts = [_][]u8{
        try ticketKeyCapsule(allocator, 0xE5),
        try v1Capsule(allocator, sampleSnap(70)),
        try v2Capsule(allocator, sampleSnap(71)),
        try v1Capsule(allocator, sampleSnap(72)),
        try ticketKeyCapsule(allocator, 0xF6),
    };
    const stream = try joinCaps(allocator, parts[0..]);
    defer allocator.free(stream);

    var open: std.AutoHashMapUnmanaged(i32, void) = .empty;
    defer open.deinit(allocator);

    const res = try adoptStream(allocator, stream, &loom, &open);

    // Safety invariants that must hold for ANY seed:
    try testing.expectEqual(@as(usize, 2), res.siblings_adopted); // siblings untouched
    try testing.expectEqual(@as(usize, 3), res.s2s_adopted + res.s2s_dropped); // all seen
    try testing.expectEqual(res.s2s_dropped, res.fds_recovered); // every drop recovered
    try testing.expectEqual(@as(usize, 0), res.fds_leaked); // never leak an fd
}

test "s2s_link too-new capsule is refused fail-closed and fd recovered on resume" {
    const allocator = testing.allocator;

    // A future binary's v3 link rides beside a good v2 link. The capsule layer
    // forward-accepts v3, but `s2s_snapshot.decode` rejects the unknown version;
    // its fd is recovered while the v2 link adopts and siblings are unaffected.
    const parts = [_][]u8{
        try v2Capsule(allocator, sampleSnap(80)),
        try tooNewCapsule(allocator, sampleSnap(81)),
        try ticketKeyCapsule(allocator, 0x1A),
    };
    const stream = try joinCaps(allocator, parts[0..]);
    defer allocator.free(stream);

    var open: std.AutoHashMapUnmanaged(i32, void) = .empty;
    defer open.deinit(allocator);

    const res = try adoptStream(allocator, stream, null, &open);
    try testing.expectEqual(@as(usize, 1), res.siblings_adopted);
    try testing.expectEqual(@as(usize, 1), res.s2s_adopted);
    try testing.expectEqual(@as(usize, 1), res.s2s_dropped);
    try testing.expectEqual(@as(usize, 1), res.fds_recovered);
    try testing.expectEqual(@as(usize, 0), res.fds_leaked);
}

test "truncated v1 s2s_link capsule body is refused and fd recovered across upgrade" {
    const allocator = testing.allocator;

    // A corrupt/partially-written inherited blob (advertised v1, but too short to
    // hold even the fixed header). Decode fails `Truncated`; the fd is still peeked
    // from the leading i32 and recovered, and the healthy sibling adopts.
    const parts = [_][]u8{
        try truncatedS2sCapsule(allocator, 1, 90),
        try ticketKeyCapsule(allocator, 0x2B),
    };
    const stream = try joinCaps(allocator, parts[0..]);
    defer allocator.free(stream);

    var open: std.AutoHashMapUnmanaged(i32, void) = .empty;
    defer open.deinit(allocator);

    const res = try adoptStream(allocator, stream, null, &open);
    try testing.expectEqual(@as(usize, 1), res.siblings_adopted);
    try testing.expectEqual(@as(usize, 0), res.s2s_adopted);
    try testing.expectEqual(@as(usize, 1), res.s2s_dropped);
    try testing.expectEqual(@as(usize, 1), res.fds_recovered);
    try testing.expectEqual(@as(usize, 0), res.fds_leaked);
}

test "empty capsule stream adopts nothing without panic on resume" {
    const allocator = testing.allocator;

    var open: std.AutoHashMapUnmanaged(i32, void) = .empty;
    defer open.deinit(allocator);

    const res = try adoptStream(allocator, &.{}, null, &open);
    try testing.expectEqual(@as(usize, 0), res.siblings_adopted);
    try testing.expectEqual(@as(usize, 0), res.s2s_adopted);
    try testing.expectEqual(@as(usize, 0), res.s2s_dropped);
    try testing.expectEqual(@as(usize, 0), res.fds_leaked);
}

test "s2s_link truncated capsule with sub-fd body neither adopts nor bogus-closes" {
    const allocator = testing.allocator;

    // A blob shorter than an i32 cannot even yield an fd — `peekFd` returns null,
    // so nothing is (bogus-)closed and nothing leaks. Fail-closed on both ends.
    var tiny: [3]u8 = .{ 1, 2, 3 };
    const d = capsule.descriptor(.s2s_link);
    const header = capsule.Header{
        .schema_id = d.schema_id,
        .kind = .s2s_link,
        .version = 1,
        .min_supported = 1,
        .max_supported = 2,
    };
    var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = &tiny }};
    const cap_bytes = try capsule.encode(allocator, .{ .header = header, .fields = fields[0..] });
    defer allocator.free(cap_bytes);

    var open: std.AutoHashMapUnmanaged(i32, void) = .empty;
    defer open.deinit(allocator);

    const res = try adoptStream(allocator, cap_bytes, null, &open);
    try testing.expectEqual(@as(usize, 0), res.s2s_adopted);
    try testing.expectEqual(@as(usize, 1), res.s2s_dropped);
    try testing.expectEqual(@as(usize, 0), res.fds_recovered); // no fd to recover
    try testing.expectEqual(@as(usize, 0), res.fds_leaked);
}
