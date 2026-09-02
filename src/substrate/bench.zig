// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `zig build bench` — the 0.7 measurement harness (release plan P0-1, wave W1-1).
//!
//! WHY THIS EXISTS
//! ---------------
//! Before this file, no performance claim about this daemon was falsifiable: there
//! was no benchmark step, no benchmark source, and no baseline artifact anywhere in
//! the tree (0.7-RELEASE-PLAN.md drift finding D-8). This harness establishes the
//! **0.5.8 baseline** so the Performance theme's later work — Ringlane unification,
//! multishot recv, provided buffer rings, `send_zc` fan-out — can be measured as a
//! DELTA against a recorded number instead of asserted.
//!
//! This is a STANDALONE, opt-in binary, deliberately NOT part of `zig build test`:
//! a wall-clock measurement is inherently noisy and folding it into the full test
//! suite would make the suite flaky. Same separation as `zig build ct-check`.
//!
//! It does **not** boot the daemon and does **not** open a fixed port. Every socket
//! it creates is loopback on an ephemeral port (`port = 0`). Nothing here touches
//! `src/substrate/io/ring.zig` — wiring the modern io_uring feature set is P0-2,
//! owned by onyx-server-reactor. This is baseline-only, by design.
//!
//! WHAT IT MEASURES
//! ----------------
//! Four hot-path stages, each isolated so a regression points at one place:
//!
//!   1. `inbound-parse`   — `proto.irc_line.parseLine` over a mixed client-line
//!                          corpus (plain, IRCv3-tagged, JOIN, long trailing,
//!                          many-param MODE). This is the per-received-line cost
//!                          on every byte a client sends. Zero-allocation by
//!                          design: `LineView` slices point into the caller's
//!                          input. Reported in ns/line and MiB/s.
//!
//!   2. `outbound-tags/*` — `proto.msgtags.composeOutbound` into a caller-provided
//!                          buffer: the primitive that builds ONE cap-variant of
//!                          an outbound line. Run as a PAIR — `/all` with all six
//!                          tags negotiated (server-time, account, msgid, label,
//!                          batch, bot) and `/none` with an empty cap set, which
//!                          is just the line copy. `/all` minus `/none` attributes
//!                          how much of per-recipient framing is tag construction
//!                          rather than the unavoidable copy. Reported in
//!                          ns/compose.
//!
//!   3. `fanout-frame`    — the channel fan-out shape at widths 1…4096. Models the
//!                          CORRECT discipline: build each distinct cap-variant
//!                          line ONCE per message, then copy the selected variant
//!                          into each recipient's inline send buffer. The falsifiable
//!                          property is the reported `variant_builds_per_msg`: it
//!                          must stay at the variant count (4) at EVERY width. If a
//!                          future change makes it scale with width, fan-out became
//!                          O(N) compose calls instead of O(N) memcpy + O(V) builds,
//!                          and this bench will say so. Reported in ns/recipient and
//!                          messages/sec.
//!
//!   4. `fabric-handoff`  — the cross-shard delivery fabric round-trip
//!                          (`daemon.reactor_fabric`): `acquire` a pooled
//!                          `DeliverBuf` → copy bytes → `sendTo` the target shard's
//!                          MPMC inbox → `wake` its eventfd → `drainWake` →
//!                          `drain` a batch → `release` every buffer. Batched at 64
//!                          messages per wake so the measurement reflects the real
//!                          cadence (one eventfd write coalesces a burst; one drain
//!                          clears it). Asserts zero drops and zero pool leaks.
//!                          Reported in ns/message. Linux-only (eventfd).
//!
//!   5. `accept`          — loopback connection-accept rate: `socket` → `connect` →
//!                          `accept4` → close both, on an ephemeral port. A
//!                          syscall-bound floor for the accept path WITHOUT the
//!                          daemon, without TLS, and without io_uring. Reported in
//!                          accepts/sec. Linux-only (raw syscalls).
//!
//! HOW TO READ THE OUTPUT
//! ----------------------
//! Each row reports, over `samples` independent timed samples of `ops` operations:
//!
//!   * `min`  — best observed ns/op: a warm cache and no preemption. This is the
//!              cleanest read on the CODE's cost and the column to compare when
//!              the machine is not idle.
//!   * `p50`  — median ns/op, the steady-state number. Throughput columns are
//!              derived from p50, never from min.
//!   * `p99`  — tail ns/op. A p99 far above p50 means scheduler noise, a cold
//!              cache, or a real tail problem; investigate before trusting a delta.
//!
//! Samples are kept deliberately SHORT (single-digit milliseconds). A long sample
//! spans many scheduler quanta, so on a busy box every sample absorbs preemption
//! and the whole distribution shifts rather than just the tail — measured here as a
//! 2-3x min-to-p50 smear at ~100 ms samples. With short samples the preemption
//! lands in p99 where it belongs. A large min-to-p50 gap is therefore a signal to
//! re-run on an idle machine, not a property of the code.
//!
//! A `layout` block follows the table with `@sizeOf` for the structs copied or
//! zero-initialized once per operation. `LineView` is returned BY VALUE from
//! `parseLine` on every received line, so its size is a direct per-line cost.
//!
//! A delta is only meaningful against a baseline captured on the SAME machine,
//! kernel, and CPU governor. The header records arch, OS, CPU count, optimize
//! mode, Zig version, and the daemon version+commit for exactly that reason;
//! `tools/bench.sh` adds the CPU model, kernel, governor, and load average.
//!
//! Rule of thumb: treat a p50 move under 5% as noise unless it reproduces across
//! two runs. `tools/bench.sh` runs the harness twice for that reason.
//!
//! WHAT IT DOES **NOT** MEASURE (named gaps — do not claim these from this file)
//! ---------------------------------------------------------------------------
//!   * TLS and kTLS on/off. The handshake and record path are not exercised here;
//!     `outbound-tags`/`fanout-frame` measure plaintext framing only.
//!   * Steady-state RSS per connection. Needs a live daemon under load; that is a
//!     separate artifact, not this binary.
//!   * `num_shards` scaling and the `world.lockWrite` command-path ceiling
//!     (release-plan D-5 / R-3). `fabric-handoff` measures the HANDOFF cost between
//!     two shards single-threaded; it says nothing about multi-core command
//!     throughput. Do not write a "scales with shards" claim from this bench.
//!   * End-to-end message round-trip latency through a real socket + reactor.
//!   * io_uring submit/complete cost — deliberately untouched (P0-2).
//!
//! TUNING (environment; Linux only — `/proc/self/environ`, since Zig 0.16 dropped
//! `std.posix.getenv` on no-libc Linux. Other targets always use the defaults.)
//!
//!   ONYX_BENCH_SAMPLES        samples per row                     (default 25)
//!   ONYX_BENCH_ITERS          iterations per sample, CPU benches  (default 4000)
//!   ONYX_BENCH_ACCEPT_ITERS   connections per sample, `accept`    (default 500)
//!   ONYX_BENCH_JSON           set to 1 to append a machine-readable JSON block
//!   ONYX_BENCH_ONLY           run only rows whose name contains this substring
//!
//! The harness SELF-VERIFIES: every stage asserts a correctness invariant on its
//! own output (the parse produced the expected command, the composed line carries
//! its tags, every fan-out copy matches its variant, the fabric dropped nothing and
//! leaked no pool slot, every connection was accepted). A violated invariant exits
//! non-zero rather than reporting a fast wrong number.

const std = @import("std");
const builtin = @import("builtin");
const onyx = @import("onyx_server");

const irc_line = onyx.proto.irc_line;
const msgtags = onyx.proto.msgtags;
const cap = onyx.proto.cap;
const reactor_fabric = onyx.daemon.reactor_fabric;
const client_model = onyx.daemon.client;

const is_linux = builtin.os.tag == .linux;

/// Upper bound on timed samples per row. Fixed so the sample buffer is inline and
/// the harness performs no allocation inside or around a measured loop.
const max_samples: usize = 256;

/// Exit code for a violated self-verification invariant. Distinct from 1 so a
/// wrapper script can tell "the harness caught itself lying" from "it crashed".
const exit_invariant: u8 = 3;

// ── Statistics ────────────────────────────────────────────────────────────────

/// One measured row: `samples` timed samples, each covering `ops` operations.
/// Percentiles are over the per-sample ns/op, so a single preempted sample moves
/// p99 and leaves p50 alone — which is the point.
pub const Row = struct {
    name: []const u8,
    /// Operations per sample (the divisor for ns/op).
    ops: u64,
    samples: usize,
    min_ns: f64,
    p50_ns: f64,
    p99_ns: f64,
    /// Bytes processed per operation, when the row has a meaningful byte rate.
    bytes_per_op: ?u64 = null,
    /// Free-form invariant witness printed alongside the row (e.g. the fan-out
    /// variant-build count, which must not scale with width).
    note: ?[]const u8 = null,

    /// Operations per second at the MEDIAN, never at the minimum. Reporting
    /// throughput from a best-case sample is how benchmarks lie.
    pub fn opsPerSec(self: Row) f64 {
        if (self.p50_ns <= 0) return 0;
        return 1_000_000_000.0 / self.p50_ns;
    }

    pub fn mibPerSec(self: Row) ?f64 {
        const b = self.bytes_per_op orelse return null;
        return self.opsPerSec() * @as(f64, @floatFromInt(b)) / (1024.0 * 1024.0);
    }
};

/// Collects per-sample elapsed times and reduces them to a `Row`.
const Samples = struct {
    buf: [max_samples]u64 = @splat(0),
    len: usize = 0,

    fn push(self: *Samples, elapsed_ns: u64) void {
        if (self.len >= max_samples) return;
        self.buf[self.len] = elapsed_ns;
        self.len += 1;
    }

    fn reduce(self: *Samples, name: []const u8, ops: u64, bytes_per_op: ?u64, note: ?[]const u8) Row {
        std.debug.assert(self.len > 0);
        std.debug.assert(ops > 0);
        const s = self.buf[0..self.len];
        std.mem.sort(u64, s, {}, std.sort.asc(u64));
        const per = @as(f64, @floatFromInt(ops));
        return .{
            .name = name,
            .ops = ops,
            .samples = self.len,
            .min_ns = @as(f64, @floatFromInt(s[0])) / per,
            .p50_ns = @as(f64, @floatFromInt(s[self.len / 2])) / per,
            .p99_ns = @as(f64, @floatFromInt(s[percentileIndex(self.len, 99)])) / per,
            .bytes_per_op = bytes_per_op,
            .note = note,
        };
    }
};

/// Index of the `p`-th percentile in a sorted slice of `len` items, clamped to the
/// last element. With few samples this collapses toward the max, which is the
/// honest reading: you cannot see a 99th percentile in 15 samples, only the worst.
fn percentileIndex(len: usize, p: usize) usize {
    if (len == 0) return 0;
    const idx = (len * p) / 100;
    return if (idx >= len) len - 1 else idx;
}

// ── Stage 1: inbound line parse ───────────────────────────────────────────────

/// A representative mix of what clients actually send: a bare PRIVMSG, an
/// IRCv3-tagged PRIVMSG, a JOIN, a long trailing payload, and a many-param MODE.
/// Deliberately NOT a single line repeated — a one-shape corpus flatters the
/// parser's branch predictor and hides per-shape cost.
const long_trailing_payload: [400]u8 = @splat('x');

const parse_corpus = [_][]const u8{
    ":nick!user@host.example PRIVMSG #channel :hello there\r\n",
    "@time=2026-07-10T12:00:00.000Z;msgid=abcdefghijklmnopqrstuv;account=nick :nick!user@host.example PRIVMSG #channel :tagged hello\r\n",
    ":nick!user@host.example JOIN #channel\r\n",
    ":nick!user@host.example PRIVMSG #channel :" ++ long_trailing_payload ++ "\r\n",
    ":irc.example MODE #channel +ovntkl nick1 nick2 secretkey 50\r\n",
    "PING :LAG1234567890\r\n",
};

fn corpusBytes() u64 {
    var total: u64 = 0;
    for (parse_corpus) |line| total += line.len;
    return total;
}

fn benchInboundParse(iters: usize, samples: usize) Row {
    // Self-verification: the corpus must actually parse, with the commands we
    // think it has. A parser change that starts rejecting these would otherwise
    // show up as a spectacular (and meaningless) speedup.
    const expected = [_][]const u8{ "PRIVMSG", "PRIVMSG", "JOIN", "PRIVMSG", "MODE", "PING" };
    for (parse_corpus, expected) |line, want| {
        const view = irc_line.parseLine(line) catch invariantFail("inbound-parse: corpus line failed to parse");
        if (!std.mem.eql(u8, view.command, want)) invariantFail("inbound-parse: unexpected command");
    }

    var st = Samples{};
    var round: usize = 0;
    // One warmup round is discarded so the first sample is not paying for a cold
    // i-cache; every later sample sees the same warm state.
    while (round < samples + 1) : (round += 1) {
        const t0 = monotonicNanos();
        var i: usize = 0;
        while (i < iters) : (i += 1) {
            for (parse_corpus) |line| {
                const view = irc_line.parseLine(line) catch unreachable;
                std.mem.doNotOptimizeAway(view.param_count);
                std.mem.doNotOptimizeAway(view.command.ptr);
            }
        }
        const t1 = monotonicNanos();
        if (round != 0) st.push(t1 - t0);
    }
    const ops = @as(u64, iters) * parse_corpus.len;
    return st.reduce("inbound-parse", ops, corpusBytes() / parse_corpus.len, "zero-alloc view parse");
}

// ── Stage 2: outbound tag composition ─────────────────────────────────────────

const compose_line = ":nick!user@host.example PRIVMSG #channel :hello there";

/// Every tag the composer can emit, so this row is the WORST-case cap variant.
/// A recipient with fewer caps is strictly cheaper.
fn fullCaps() cap.CapSet {
    var set = cap.CapSet.empty();
    set.add(.server_time);
    set.add(.account_tag);
    set.add(.msgid);
    set.add(.labeled_response);
    set.add(.batch);
    set.add(.bot);
    return set;
}

fn fullTags() msgtags.OutboundTags {
    return .{
        .server_time_millis = 1_783_000_000_000,
        .account = "nick",
        .msgid = .{ .counter = 1, .rng = 0x5eed_1234_5678_9abc },
        .label = "l1",
        .batch = "b1",
        .bot = true,
    };
}

/// Compose the same line for a given cap set. Run twice — once with every tag
/// negotiated and once with none — so the DELTA attributes how much of the
/// per-recipient framing cost is tag construction (server-time formatting, base62
/// msgid, escaped values) versus the unavoidable line copy. Without both rows a
/// "framing is slow" claim has no denominator.
fn benchOutboundTags(
    caps: cap.CapSet,
    expect_tags: bool,
    name: []const u8,
    note: []const u8,
    iters: usize,
    samples: usize,
) Row {
    var out: [1024]u8 = undefined;
    var tags = fullTags();

    // Self-verification: with caps the composed line must carry tags and still end
    // with the original; without caps it must be an exact copy. A composer that
    // silently no-ops would otherwise look spectacularly fast.
    {
        const got = msgtags.composeOutbound(msgtags.default_config, caps, tags, compose_line, &out) catch
            invariantFail("outbound-tags: composeOutbound failed");
        if (!std.mem.endsWith(u8, got, compose_line)) invariantFail("outbound-tags: original line not preserved");
        if (expect_tags) {
            if (got.len <= compose_line.len) invariantFail("outbound-tags: no tags were prefixed");
            if (got[0] != '@') invariantFail("outbound-tags: composed line does not start with '@'");
        } else {
            if (got.len != compose_line.len) invariantFail("outbound-tags: uncapped compose changed the line length");
        }
    }

    var st = Samples{};
    var round: usize = 0;
    while (round < samples + 1) : (round += 1) {
        const t0 = monotonicNanos();
        var i: usize = 0;
        while (i < iters) : (i += 1) {
            // Vary the msgid counter so the base62 encoder cannot be hoisted out
            // of the loop as a loop-invariant computation.
            tags.msgid.?.counter = i;
            const got = msgtags.composeOutbound(msgtags.default_config, caps, tags, compose_line, &out) catch unreachable;
            std.mem.doNotOptimizeAway(got.len);
        }
        const t1 = monotonicNanos();
        if (round != 0) st.push(t1 - t0);
    }
    return st.reduce(name, iters, null, note);
}

// ── Stage 3: channel fan-out framing ──────────────────────────────────────────

/// The distinct cap variants a real channel fan-out has to produce. Recipients
/// cluster onto a handful of cap combinations, which is exactly why the correct
/// shape is "build V variants once, memcpy per recipient".
const fanout_variants = 4;

/// Per-recipient inline send-buffer stride. Mirrors the shape of the daemon's
/// per-connection inline `send_buf` (a fixed array, never a growable one) — the
/// kernel only ever sees inline buffers, so the fan-out copy target is a fixed
/// stride, not an ArrayList append.
const fanout_stride = 640;

const fanout_widths = [_]usize{ 1, 8, 64, 512, 4096 };

fn variantCaps(v: usize) cap.CapSet {
    var set = cap.CapSet.empty();
    // v0: no caps at all (a bare legacy client). v1..v3 add tags cumulatively.
    if (v >= 1) set.add(.server_time);
    if (v >= 2) set.add(.msgid);
    if (v >= 3) {
        set.add(.account_tag);
        set.add(.bot);
    }
    return set;
}

/// Fan-out one message to `width` recipients using the pooled/caller-provided
/// discipline, writing into `sink` (a pre-allocated `width * fanout_stride`
/// scratch region standing in for the recipients' inline send buffers).
///
/// Returns the number of `composeOutbound` calls performed. This is the whole
/// point of the row: it must equal `fanout_variants` regardless of `width`.
fn fanoutOnce(width: usize, sink: []u8, tags: msgtags.OutboundTags) usize {
    // Build each distinct cap-variant line ONCE, into stack-fixed buffers.
    var variant_buf: [fanout_variants][fanout_stride]u8 = undefined;
    var variant_len: [fanout_variants]usize = @splat(0);
    var builds: usize = 0;
    for (0..fanout_variants) |v| {
        const got = msgtags.composeOutbound(
            msgtags.default_config,
            variantCaps(v),
            tags,
            compose_line,
            &variant_buf[v],
        ) catch unreachable;
        variant_len[v] = got.len;
        builds += 1;
    }

    // Then per recipient: select the variant and copy. No allocation, no compose.
    var i: usize = 0;
    while (i < width) : (i += 1) {
        const v = i % fanout_variants;
        const dst = sink[i * fanout_stride ..][0..variant_len[v]];
        @memcpy(dst, variant_buf[v][0..variant_len[v]]);
        std.mem.doNotOptimizeAway(dst.ptr);
    }
    return builds;
}

fn benchFanout(alloc: std.mem.Allocator, width: usize, iters: usize, samples: usize, name: []const u8) Row {
    // The recipient send-buffer region is allocated ONCE, outside every timed
    // loop — the same way the daemon reserves its client table to the maximum up
    // front so ConnState slots (and thus io_uring-armed buffer addresses) never
    // move. A per-message allocation here would measure the allocator, not fan-out.
    const sink = alloc.alloc(u8, width * fanout_stride) catch
        invariantFail("fanout: sink allocation failed");
    defer alloc.free(sink);
    @memset(sink, 0);

    const tags = fullTags();

    // Self-verification: every recipient's slot must hold the bytes of its own
    // variant, and the build count must not scale with width.
    {
        const builds = fanoutOnce(width, sink, tags);
        if (builds != fanout_variants) invariantFail("fanout: variant build count is not the variant count");
        var check: [fanout_stride]u8 = undefined;
        for (0..@min(width, 16)) |i| {
            const v = i % fanout_variants;
            const want = msgtags.composeOutbound(msgtags.default_config, variantCaps(v), tags, compose_line, &check) catch
                invariantFail("fanout: verification compose failed");
            if (!std.mem.eql(u8, sink[i * fanout_stride ..][0..want.len], want))
                invariantFail("fanout: recipient slot does not match its cap variant");
        }
    }

    // Scale iterations down as width grows so every row does comparable total
    // work; otherwise width=4096 would run 4096x longer than width=1.
    const msgs_per_sample = @max(@as(usize, 1), iters / width);

    var st = Samples{};
    var round: usize = 0;
    while (round < samples + 1) : (round += 1) {
        const t0 = monotonicNanos();
        var i: usize = 0;
        while (i < msgs_per_sample) : (i += 1) {
            std.mem.doNotOptimizeAway(fanoutOnce(width, sink, tags));
        }
        const t1 = monotonicNanos();
        if (round != 0) st.push(t1 - t0);
    }

    // ops = recipient deliveries, so ns/op is directly comparable across widths.
    const ops = @as(u64, msgs_per_sample) * @as(u64, width);
    return st.reduce(name, ops, null, "variant_builds_per_msg=4 (must not scale with width)");
}

// ── Stage 4: cross-shard delivery fabric ──────────────────────────────────────

/// Messages handed off per wake. The fabric's wake eventfd is non-semaphore and
/// coalescing: N writes collapse into one readiness, and one `drainWake` clears
/// them. Batching here reflects that real cadence instead of paying an eventfd
/// syscall per message, which no sane sender does.
const fabric_batch: usize = 64;

fn benchFabricHandoff(alloc: std.mem.Allocator, iters: usize, samples: usize) ?Row {
    if (!is_linux) return null;

    var fabric = reactor_fabric.ReactorFabric.init(alloc, 2) catch return null;
    defer fabric.deinit();

    const payload = ":nick!user@host.example PRIVMSG #channel :cross-shard delivery payload\r\n";
    const to = client_model.ClientId{ .shard = 1, .slot = 0, .gen = 1 };
    var drained: [fabric_batch]reactor_fabric.DeliverMsg = undefined;

    // One round-trip, verified end to end before anything is timed.
    {
        const buf = fabric.acquire(1, payload) orelse invariantFail("fabric: pool empty on a fresh fabric");
        if (!std.mem.eql(u8, fabric.bytes(buf), payload)) invariantFail("fabric: acquired buffer does not hold the payload");
        if (!fabric.sendTo(1, .{ .to = to, .buf = buf })) invariantFail("fabric: sendTo failed on an empty inbox");
        fabric.wake(1);
        fabric.drainWake(1);
        const n = fabric.drain(1, drained[0..]);
        if (n != 1) invariantFail("fabric: drain did not return the single queued message");
        if (!std.mem.eql(u8, fabric.bytes(drained[0].buf), payload)) invariantFail("fabric: drained bytes differ from sent bytes");
        fabric.release(1, drained[0].buf);
    }

    const batches_per_sample = @max(@as(usize, 1), iters / fabric_batch);

    var st = Samples{};
    var round: usize = 0;
    while (round < samples + 1) : (round += 1) {
        const t0 = monotonicNanos();
        var b: usize = 0;
        while (b < batches_per_sample) : (b += 1) {
            // Sender side: acquire from the target shard's pool, copy, enqueue.
            // Wake strictly AFTER the enqueue — the missed-wake ordering.
            var pushed: usize = 0;
            while (pushed < fabric_batch) : (pushed += 1) {
                const buf = fabric.acquire(1, payload) orelse break;
                if (!fabric.sendTo(1, .{ .to = to, .buf = buf })) {
                    fabric.release(1, buf);
                    break;
                }
            }
            fabric.wake(1);

            // Owner side: one drainWake clears the coalesced burst, one popBatch
            // takes the whole batch, and every buffer goes back exactly once.
            fabric.drainWake(1);
            const n = fabric.drain(1, drained[0..]);
            if (n != pushed) invariantFail("fabric: drained count differs from pushed count");
            for (drained[0..n]) |m| fabric.release(1, m.buf);
        }
        const t1 = monotonicNanos();
        if (round != 0) st.push(t1 - t0);
    }

    // The fabric must have shed nothing: a drop would mean the batch outran the
    // inbox and the "ns/message" number covers fewer messages than it claims.
    if (fabric.droppedCount() != 0) invariantFail("fabric: messages were dropped under back-pressure");

    // And the pool must be whole again — every acquire released exactly once. If a
    // slot leaked, this final acquire of a full batch would come up short.
    {
        var reacquired: usize = 0;
        var held: [reactor_fabric.ReactorFabric.pool_slots]*reactor_fabric.DeliverBuf = undefined;
        while (reacquired < held.len) : (reacquired += 1) {
            held[reacquired] = fabric.acquire(1, payload) orelse break;
        }
        for (held[0..reacquired]) |buf| fabric.release(1, buf);
        if (reacquired != reactor_fabric.ReactorFabric.pool_slots)
            invariantFail("fabric: pool slots leaked (fewer buffers available than at init)");
    }

    const ops = @as(u64, batches_per_sample) * @as(u64, fabric_batch);
    return st.reduce("fabric-handoff", ops, payload.len, "batch=64 per wake, 0 drops, 0 pool leaks");
}

// ── Stage 5: loopback connection-accept rate ──────────────────────────────────

fn benchAccept(iters: usize, samples: usize) ?Row {
    if (!is_linux) return null;
    const linux = std.os.linux;
    const posix = std.posix;

    const listen_rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
    if (posix.errno(listen_rc) != .SUCCESS) return null;
    const listen_fd: linux.fd_t = @intCast(listen_rc);
    defer _ = linux.close(listen_fd);

    // Ephemeral port on loopback. NEVER a fixed port: this harness must not be
    // mistakable for the daemon, which listens on 6680.
    var addr = linux.sockaddr.in{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f00_0001) };
    if (posix.errno(linux.bind(listen_fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return null;
    // Backlog comfortably above the per-sample burst so a full accept queue never
    // silently turns this into a measurement of SYN retransmit timers.
    if (posix.errno(linux.listen(listen_fd, 512)) != .SUCCESS) return null;

    var storage: posix.sockaddr.storage = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    if (posix.errno(linux.getsockname(listen_fd, @ptrCast(&storage), &slen)) != .SUCCESS) return null;
    addr.port = (@as(*const linux.sockaddr.in, @ptrCast(@alignCast(&storage)))).port;

    var st = Samples{};
    var round: usize = 0;
    while (round < samples + 1) : (round += 1) {
        var accepted: usize = 0;
        const t0 = monotonicNanos();
        var i: usize = 0;
        while (i < iters) : (i += 1) {
            const c_rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
            if (posix.errno(c_rc) != .SUCCESS) break;
            const client_fd: linux.fd_t = @intCast(c_rc);
            if (posix.errno(linux.connect(client_fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
                _ = linux.close(client_fd);
                break;
            }
            const a_rc = linux.accept4(listen_fd, null, null, 0);
            if (posix.errno(a_rc) != .SUCCESS) {
                _ = linux.close(client_fd);
                break;
            }
            _ = linux.close(@as(linux.fd_t, @intCast(a_rc)));
            _ = linux.close(client_fd);
            accepted += 1;
        }
        const t1 = monotonicNanos();
        // Self-verification: a short sample would divide real time by a claimed
        // op count that never happened, inflating the rate.
        if (accepted != iters) invariantFail("accept: not every connection was accepted");
        if (round != 0) st.push(t1 - t0);
    }
    return st.reduce("accept", iters, null, "loopback, ephemeral port, no TLS, no io_uring");
}

// ── Reporting ─────────────────────────────────────────────────────────────────

fn printHeader(rows_note: []const u8) void {
    const cpus = std.Thread.getCpuCount() catch 0;
    std.debug.print(
        \\onyx-server bench — 0.7 measurement harness (P0-1 baseline)
        \\
        \\  version        {s}
        \\  arch/os        {s}-{s}
        \\  cpu count      {d}
        \\  optimize       {s}
        \\  zig            {s}
        \\  scope          {s}
        \\
        \\  Throughput is derived from p50, never from min. Compare only against a
        \\  baseline captured on THIS machine, kernel, and CPU governor.
        \\
        \\
    , .{
        onyx.version,
        @tagName(builtin.cpu.arch),
        @tagName(builtin.os.tag),
        cpus,
        @tagName(builtin.mode),
        builtin.zig_version_string,
        rows_note,
    });
    std.debug.print(
        "{s:<24} {s:>10} {s:>7} {s:>12} {s:>12} {s:>12} {s:>14} {s:>11}\n",
        .{ "row", "ops", "samp", "min ns/op", "p50 ns/op", "p99 ns/op", "ops/sec (p50)", "MiB/s (p50)" },
    );
    const rule: [108]u8 = @splat('-');
    std.debug.print("{s}\n", .{&rule});
}

fn printRow(row: Row) void {
    if (row.mibPerSec()) |mib| {
        std.debug.print(
            "{s:<24} {d:>10} {d:>7} {d:>12.2} {d:>12.2} {d:>12.2} {d:>14.0} {d:>11.1}\n",
            .{ row.name, row.ops, row.samples, row.min_ns, row.p50_ns, row.p99_ns, row.opsPerSec(), mib },
        );
    } else {
        std.debug.print(
            "{s:<24} {d:>10} {d:>7} {d:>12.2} {d:>12.2} {d:>12.2} {d:>14.0} {s:>11}\n",
            .{ row.name, row.ops, row.samples, row.min_ns, row.p50_ns, row.p99_ns, row.opsPerSec(), "-" },
        );
    }
}

fn printNotes(rows: []const Row) void {
    std.debug.print("\nnotes\n", .{});
    for (rows) |row| {
        if (row.note) |note| std.debug.print("  {s:<22} {s}\n", .{ row.name, note });
    }
}

/// Sizes of the structs that get copied or zero-initialized once per operation on
/// the paths above. Printed unconditionally because a layout regression is
/// invisible in a ns/op column until it is large — and because `LineView` is
/// returned BY VALUE from `parseLine` on every received line, so its size is a
/// direct per-line cost, not a detail.
fn printLayout() void {
    std.debug.print(
        \\
        \\layout (@sizeOf, bytes) — structs copied or zero-initialized per operation
        \\  proto.irc_line.LineView          {d:>8}   returned by value per parsed line
        \\  daemon.deliver_handle.DeliverMsg {d:>8}   crosses the shard mailbox by value
        \\  daemon.deliver_handle.DeliverBuf {d:>8}   pooled; {d} slots per shard
        \\
    , .{
        @sizeOf(irc_line.LineView),
        @sizeOf(reactor_fabric.DeliverMsg),
        @sizeOf(reactor_fabric.DeliverBuf),
        reactor_fabric.ReactorFabric.pool_slots,
    });
}

/// Machine-readable output for a baseline artifact, or for a future regression
/// tripwire once a baseline has proven stable across machines. Hand-rolled so the
/// harness needs no allocator and no serializer on a path that must not fail.
fn printJson(rows: []const Row) void {
    const cpus = std.Thread.getCpuCount() catch 0;
    std.debug.print(
        \\
        \\{{"schema":"onyx-bench/1","version":"{s}","arch":"{s}","os":"{s}","cpus":{d},"optimize":"{s}","zig":"{s}","rows":[
    , .{
        onyx.version,
        @tagName(builtin.cpu.arch),
        @tagName(builtin.os.tag),
        cpus,
        @tagName(builtin.mode),
        builtin.zig_version_string,
    });
    for (rows, 0..) |row, i| {
        if (i != 0) std.debug.print(",", .{});
        std.debug.print(
            \\{{"name":"{s}","ops":{d},"samples":{d},"min_ns_per_op":{d:.4},"p50_ns_per_op":{d:.4},"p99_ns_per_op":{d:.4},"ops_per_sec_p50":{d:.1}}}
        , .{ row.name, row.ops, row.samples, row.min_ns, row.p50_ns, row.p99_ns, row.opsPerSec() });
    }
    std.debug.print("]}}\n", .{});
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Defaults are chosen so ONE sample lasts single-digit milliseconds. That is
    // deliberate: a long sample spans many scheduler quanta, so on a loaded box
    // every sample absorbs preemption and the whole distribution shifts (measured
    // 2-3x min-to-p50 smear at 100 ms samples). Short samples keep preemption
    // contained in the tail, where p99 reports it, and leave `min` a clean read on
    // the code's actual cost. Raise ONYX_BENCH_ITERS only on an idle machine.
    const samples = @min(max_samples, @max(@as(usize, 3), envUsize("ONYX_BENCH_SAMPLES", 25)));
    const iters = @max(@as(usize, 100), envUsize("ONYX_BENCH_ITERS", 4_000));
    const accept_iters = @max(@as(usize, 50), envUsize("ONYX_BENCH_ACCEPT_ITERS", 500));
    const want_json = envUsize("ONYX_BENCH_JSON", 0) != 0;
    var only_buf: [4096]u8 = undefined;
    const only = envValue("ONYX_BENCH_ONLY", &only_buf);

    // Fixed-capacity row buffer: the harness allocates nothing for its own
    // bookkeeping, so a report can never fail for want of memory.
    var rows_buf: [8 + fanout_widths.len]Row = undefined;
    var rows_len: usize = 0;
    var width_names: [fanout_widths.len][32]u8 = undefined;

    printHeader(if (only) |o| o else "all rows");

    if (selected(only, "inbound-parse")) {
        const row = benchInboundParse(iters, samples);
        printRow(row);
        rows_buf[rows_len] = row;
        rows_len += 1;
    }
    if (selected(only, "outbound-tags/all")) {
        const row = benchOutboundTags(fullCaps(), true, "outbound-tags/all", "6 tags: time, account, msgid, label, batch, bot", iters, samples);
        printRow(row);
        rows_buf[rows_len] = row;
        rows_len += 1;
    }
    if (selected(only, "outbound-tags/none")) {
        const row = benchOutboundTags(cap.CapSet.empty(), false, "outbound-tags/none", "no caps: the bare line-copy floor (subtract to attribute tag cost)", iters, samples);
        printRow(row);
        rows_buf[rows_len] = row;
        rows_len += 1;
    }
    for (fanout_widths, 0..) |width, wi| {
        const name = std.fmt.bufPrint(&width_names[wi], "fanout-frame/w{d}", .{width}) catch unreachable;
        if (!selected(only, name)) continue;
        const row = benchFanout(alloc, width, iters, samples, name);
        printRow(row);
        rows_buf[rows_len] = row;
        rows_len += 1;
    }
    if (selected(only, "fabric-handoff")) {
        if (benchFabricHandoff(alloc, iters, samples)) |row| {
            printRow(row);
            rows_buf[rows_len] = row;
            rows_len += 1;
        } else {
            std.debug.print("{s:<24} skipped (needs Linux eventfd)\n", .{"fabric-handoff"});
        }
    }
    if (selected(only, "accept")) {
        if (benchAccept(accept_iters, samples)) |row| {
            printRow(row);
            rows_buf[rows_len] = row;
            rows_len += 1;
        } else {
            std.debug.print("{s:<24} skipped (needs Linux sockets)\n", .{"accept"});
        }
    }

    if (rows_len == 0) {
        std.debug.print("\nno rows matched ONYX_BENCH_ONLY; nothing measured\n", .{});
        return;
    }

    printNotes(rows_buf[0..rows_len]);
    printLayout();
    if (want_json) printJson(rows_buf[0..rows_len]);
}

fn selected(only: ?[]const u8, name: []const u8) bool {
    const filter = only orelse return true;
    const trimmed = std.mem.trim(u8, filter, " \t\r\n");
    if (trimmed.len == 0) return true;
    return std.mem.indexOf(u8, name, trimmed) != null;
}

/// A violated self-verification invariant. The harness refuses to report a number
/// it cannot stand behind: a fast wrong measurement is worse than no measurement.
fn invariantFail(comptime what: []const u8) noreturn {
    std.debug.print("\n[bench] INVARIANT VIOLATED: {s}\n", .{what});
    std.process.exit(exit_invariant);
}

// ── Platform helpers ──────────────────────────────────────────────────────────

/// Monotonic clock in nanoseconds. Mirrors `tools/constant_time_check.zig`'s
/// per-OS sourcing; the operations timed here run in nanoseconds to microseconds,
/// so a wall-clock or coarse source would be useless.
fn monotonicNanos() u64 {
    switch (builtin.os.tag) {
        .linux => {
            var ts: std.os.linux.timespec = undefined;
            _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts);
            return nsFrom(@intCast(ts.sec), @intCast(ts.nsec));
        },
        .windows => {
            var freq: i64 = 0;
            var cnt: i64 = 0;
            _ = std.os.windows.ntdll.RtlQueryPerformanceFrequency(&freq);
            _ = std.os.windows.ntdll.RtlQueryPerformanceCounter(&cnt);
            if (freq == 0) return 0;
            return @intCast(@divTrunc(@as(i128, cnt) * 1_000_000_000, @as(i128, freq)));
        },
        else => {
            var ts: std.c.timespec = undefined;
            _ = std.c.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts);
            return nsFrom(@intCast(ts.sec), @intCast(ts.nsec));
        },
    }
}

fn nsFrom(sec: i64, nsec: i64) u64 {
    return @as(u64, @intCast(sec)) * 1_000_000_000 + @as(u64, @intCast(nsec));
}

/// Parse an unsigned environment override, falling back to `default` on absence
/// or a malformed value.
fn envUsize(name: []const u8, default: usize) usize {
    var buf: [16384]u8 = undefined;
    const raw = envValue(name, &buf) orelse return default;
    return std.fmt.parseInt(usize, std.mem.trim(u8, raw, " \t\r\n"), 10) catch default;
}

/// Look up an environment variable by scanning `/proc/self/environ` (NUL-separated
/// `KEY=VALUE` records). Returns a slice into `buf`. Linux-only; returns null
/// elsewhere, so other targets always take the defaults.
fn envValue(name: []const u8, buf: []u8) ?[]const u8 {
    if (!is_linux) return null;
    const linux = std.os.linux;
    const rc = linux.open("/proc/self/environ", .{ .ACCMODE = .RDONLY }, 0);
    const sfd: isize = @bitCast(rc);
    if (sfd < 0) return null;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);

    var total: usize = 0;
    while (total < buf.len) {
        const n = linux.read(fd, buf[total..].ptr, buf.len - total);
        const sn: isize = @bitCast(n);
        if (sn <= 0) break;
        total += n;
    }
    var it = std.mem.splitScalar(u8, buf[0..total], 0);
    while (it.next()) |record| {
        const eq = std.mem.indexOfScalar(u8, record, '=') orelse continue;
        if (std.mem.eql(u8, record[0..eq], name)) return record[eq + 1 ..];
    }
    return null;
}
