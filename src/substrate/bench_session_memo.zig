// SPDX-License-Identifier: AGPL-3.0-or-later
//! Direct-leaf SESSION_REPLICA signed inventory duplicate measurement.
//! Setup/signing/prepopulation/checkpoint comparison are outside timed regions.
//! The logical clock remains fixed and valid; awake monotonic time measures
//! execution only. Sets1/4 fit the four-slot memo; cyclic set8 must thrash.
//! This does NOT measure a daemon, peer authentication, TCP, Helix, contention,
//! client throughput or real expiry behavior. Never extrapolate mesh capacity.
const std = @import("std");
const builtin = @import("builtin");
const onyx = @import("onyx_server");
const replica = onyx.daemon.helix.session_replica;
const sign = onyx.crypto.sign;
const logical_now: i64 = 200;
const max_set: usize = 8;
const samples: usize = 3;
const Allocator = std.mem.Allocator;

fn require(ok: bool) error{InvariantMismatch}!void {
    if (!ok) return error.InvariantMismatch;
}

// Checked form of the existing substrate benchmark's per-OS monotonic timer.
fn awakeNanos() !u64 {
    if (comptime builtin.os.tag == .windows) {
        var frequency: i64 = 0;
        var count: i64 = 0;
        if (!std.os.windows.ntdll.RtlQueryPerformanceFrequency(&frequency).toBool() or
            !std.os.windows.ntdll.RtlQueryPerformanceCounter(&count).toBool() or
            frequency <= 0 or count < 0) return error.ClockUnavailable;
        return std.math.cast(u64, @divTrunc(@as(i128, count) * 1_000_000_000, frequency)) orelse error.ClockUnavailable;
    } else if (comptime builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = .{ .sec = 0, .nsec = 0 };
        if (std.os.linux.errno(std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts)) != .SUCCESS) return error.ClockUnavailable;
        if (ts.sec < 0 or ts.nsec < 0 or ts.nsec >= 1_000_000_000) return error.ClockUnavailable;
        return std.math.cast(u64, @as(i128, ts.sec) * 1_000_000_000 + ts.nsec) orelse error.ClockUnavailable;
    } else if (comptime builtin.os.tag == .openbsd) {
        var ts: std.c.timespec = .{ .sec = 0, .nsec = 0 };
        if (std.c.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts) != 0 or ts.sec < 0 or ts.nsec < 0 or ts.nsec >= 1_000_000_000) return error.ClockUnavailable;
        return std.math.cast(u64, @as(i128, ts.sec) * 1_000_000_000 + ts.nsec) orelse error.ClockUnavailable;
    } else return error.UnsupportedClock;
}

fn elapsed(start: u64) !u64 {
    const end = try awakeNanos();
    if (end < start) return error.ClockRegressed;
    return end - start;
}

const Fixture = struct {
    allocator: Allocator,
    wires: [max_set][]u8 = undefined,
    signed: [max_set]replica.SignedOffer = undefined,
    initialized: usize = 0,
    authority: replica.OfferMemoAuthority,

    fn init(a: Allocator) !Fixture {
        var key = try sign.KeyPair.fromSeed(@splat(0xB1));
        defer key.deinit();
        var f = Fixture{ .allocator = a, .authority = .{ .declared = true, .epoch = 7, .roster_digest = @splat(0x51) } };
        errdefer f.deinit();
        const origin = onyx.crypto.node_short_id.shortId(onyx.daemon.node_identity.nodeIdFromPublicKey(key.public_key));
        for (0..max_set) |i| {
            var inventory_bytes: [replica.inventory_row_len]u8 = undefined;
            const inventory = try replica.encodeInventory(&inventory_bytes, &.{.{ .attachment_id = @splat(@as(u8, @intCast(i + 1))), .signon_ms = 100, .attached = true }});
            // Valid current metadata-only inventory: no resume profile is
            // invented. Every identity differs only in token/revision/inventory.
            const wire = try replica.encodeOffer(a, .{
                .operation = .inventory_upsert,
                .resume_eligible = false,
                .inventory = inventory,
                .token = @splat(@as(u8, @intCast(i + 1))),
                .account = "benchmark-account",
                .nick = "",
                .snapshot = "",
                .revision = .{ .epoch = 100, .sequence = (@as(u64, 100) << 16) + i, .origin_node = origin },
                .issued_at_ms = 100,
                .expires_at_ms = 10_000,
            }, &key);
            f.wires[i] = wire;
            f.initialized += 1;
            f.signed[i] = try replica.decodeOffer(wire);
            try require(f.signed[i].transcript.len <= replica.OfferSignatureMemo.max_transcript_bytes);
        }
        return f;
    }
    fn deinit(f: *Fixture) void {
        for (f.wires[0..f.initialized]) |wire| {
            std.crypto.secureZero(u8, wire);
            f.allocator.free(wire);
        }
        f.* = undefined;
    }
};

fn checkpointsEqual(a: Allocator, ordinary: *const replica.Store, memoized: *const replica.Store) !void {
    const left = try ordinary.encodeUpgradeCheckpoint(a, logical_now);
    defer a.free(left);
    const right = try memoized.encodeUpgradeCheckpoint(a, logical_now);
    defer a.free(right);
    try require(std.mem.eql(u8, left, right));
}

const Timed = struct { calls: usize, awake_ns: u64 };
fn ordinaryRun(store: *replica.Store, f: *const Fixture, width: usize, rounds: usize) !Timed {
    const start = try awakeNanos();
    for (0..rounds) |_| for (f.signed[0..width]) |signed| {
        const applied = try store.applySignedOffer(signed, 9, logical_now);
        try require(applied.disposition == .duplicate);
    };
    return .{ .calls = width * rounds, .awake_ns = try elapsed(start) };
}
fn memoRun(store: *replica.Store, memo: *replica.OfferSignatureMemo, f: *const Fixture, width: usize, rounds: usize) !Timed {
    const start = try awakeNanos();
    for (0..rounds) |_| for (f.signed[0..width]) |signed| {
        const applied = try store.applySignedOfferMemoized(signed, 9, logical_now, memo, f.authority);
        try require(applied.disposition == .duplicate);
    };
    return .{ .calls = width * rounds, .awake_ns = try elapsed(start) };
}

fn printRow(width: usize, sample: usize, phase: []const u8, arm: []const u8, timed: Timed, delta: ?replica.OfferSignatureMemo.Stats) void {
    // Fixed labels/counts only; signed bytes, token, account and key never print.
    std.debug.print("{{\"scope\":\"direct_leaf_inventory_duplicates\",\"working_set\":{d},\"sample\":{d},\"phase\":\"{s}\",\"arm\":\"{s}\",\"calls\":{d},\"awake_ns\":{d}", .{ width, sample, phase, arm, timed.calls, timed.awake_ns });
    if (delta) |s| {
        std.debug.print(",\"signature_checks\":{d},\"cache_hits\":{d},\"fallbacks\":{d},\"counter_basis\":\"production_memo_stats\"}}\n", .{ s.signature_checks, s.cache_hits, s.fallbacks });
    } else {
        // Ordinary API has no observation counter. Its source path verifies
        // once per call; keep that expectation distinct from measured stats.
        std.debug.print(",\"signature_checks\":null,\"signature_checks_source_expected\":{d},\"counter_basis\":\"ordinary_API_uninstrumented\"}}\n", .{timed.calls});
    }
}

fn runCase(a: Allocator, f: *const Fixture, width: usize, sample: usize, rounds: usize) !void {
    var ordinary = replica.Store.init(a);
    defer ordinary.deinit();
    var memoized = replica.Store.init(a);
    defer memoized.deinit();
    var memo: replica.OfferSignatureMemo = .{};
    defer memo.deinit();
    for (f.signed[0..width]) |signed| {
        try require((try ordinary.applySignedOffer(signed, 9, logical_now)).disposition == .inserted);
        try require((try memoized.applySignedOffer(signed, 9, logical_now)).disposition == .inserted);
    }
    try checkpointsEqual(a, &ordinary, &memoized);
    try require(std.meta.eql(replica.OfferSignatureMemo.Stats{}, memo.stats()));
    const plain_cold = try ordinaryRun(&ordinary, f, width, 1);
    const memo_cold = try memoRun(&memoized, &memo, f, width, 1);
    const cold = memo.stats();
    try require(cold.signature_checks == width and cold.cache_hits == 0 and cold.fallbacks == 0);
    try checkpointsEqual(a, &ordinary, &memoized);
    const plain_warm = try ordinaryRun(&ordinary, f, width, rounds);
    const memo_warm = try memoRun(&memoized, &memo, f, width, rounds);
    const warm = memo.stats();
    const delta: replica.OfferSignatureMemo.Stats = .{ .signature_checks = warm.signature_checks - cold.signature_checks, .cache_hits = warm.cache_hits - cold.cache_hits, .fallbacks = warm.fallbacks - cold.fallbacks };
    const fits = width <= replica.OfferSignatureMemo.capacity;
    try require(delta.signature_checks == (if (fits) @as(u64, 0) else @as(u64, @intCast(memo_warm.calls))));
    try require(delta.cache_hits == (if (fits) @as(u64, @intCast(memo_warm.calls)) else @as(u64, 0)) and delta.fallbacks == 0);
    try checkpointsEqual(a, &ordinary, &memoized);
    // Emit timing rows only after BOTH arms and all source invariants pass.
    printRow(width, sample, "cold_memo", "ordinary", plain_cold, null);
    printRow(width, sample, "cold_memo", "memoized", memo_cold, cold);
    printRow(width, sample, "warm_cyclic", "ordinary", plain_warm, null);
    printRow(width, sample, "warm_cyclic", "memoized", memo_warm, delta);
}

fn run(init: std.process.Init) !void {
    var args = try std.process.Args.iterateAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    var rounds: usize = 256;
    if (args.next()) |flag| {
        if (!std.mem.eql(u8, flag, "--iterations")) return error.InvalidArguments;
        rounds = try std.fmt.parseInt(usize, args.next() orelse return error.InvalidArguments, 10);
        if (rounds == 0 or rounds > 4096 or args.next() != null) return error.InvalidArguments;
    }
    var f = try Fixture.init(init.gpa);
    defer f.deinit();
    std.debug.print("scope=direct_leaf_only version={s} zig={s} arch={s} os={s} optimize={s} iterations={d} samples={d} logical_now_ms={d} inventory_rows=1 resume_eligible=false; not daemon or mesh throughput\n", .{ onyx.version, builtin.zig_version_string, @tagName(builtin.cpu.arch), @tagName(builtin.os.tag), @tagName(builtin.mode), rounds, samples, logical_now });
    for ([_]usize{ 1, 4, 8 }) |width| for (0..samples) |sample| try runCase(init.gpa, &f, width, sample, rounds);
    std.debug.print("validated_cases=9 timing_rows=36; no end_to_end_throughput_claim\n", .{});
}

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        std.debug.print("session-memo-bench failed class={s}; no successful benchmark conclusion\n", .{@errorName(err)});
        std.process.exit(1);
    };
}
