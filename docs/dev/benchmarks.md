# Benchmarks — how to run and interpret `zig build bench`
*Developer guide for the 0.7 measurement harness (`src/substrate/bench.zig`), release plan P0-1.*

Before this harness, no performance claim about Onyx Server was falsifiable: there was no
`bench` step, no benchmark source, and no recorded baseline anywhere in the tree. The 0.7
release plan makes that a P0 blocker — **risk R-4**, "performance claims remain unfalsifiable
if P0-1 slips" — and gates the Performance theme behind it: `zig build bench` must produce a
baseline before P0-2 (io_uring wins) may claim anything.

This harness establishes that baseline. It is **measurement only**. It deliberately does not
touch `src/substrate/io/ring.zig`; wiring the modern io_uring feature set is P0-2, owned by
onyx-server-reactor.

## Running it

```sh
zig build bench                  # build ReleaseFast + run every row
tools/bench.sh                   # same, twice, with machine provenance
tools/bench.sh -o docs/audit/bench-baseline-0.5.8.md
tools/bench.sh --quick           # smoke check, NOT a baseline
zig build bench-live             # throwaway daemon: TLS / shards / ring axes
zig build bench-live -- --quick  # one plaintext live cell
tools/bench.sh --live -o docs/audit/bench-live-0.7.0-rc.1.md
```

`zig build bench` compiles the harness as its own ReleaseFast module and installs it to
`zig-out/bin/onyx-server-bench`, so you can also re-run the exact same binary under `taskset`
or `nice` without going back through the build graph:

```sh
taskset -c 2 ./zig-out/bin/onyx-server-bench
```

The step is **not** part of `zig build test`, and not part of `all-checks`. A wall-clock
measurement is inherently noisy, and folding it into the full suite would make the suite
flaky. Wiring the harness as a regression tripwire is future work, and only after a baseline
has proven stable across machines. This is the same separation `zig build ct-check` uses.

The offline step never boots the daemon or opens a fixed port — every socket that
harness creates is loopback on an ephemeral port. Live axes use `zig build bench-live`
(see below), which boots a throwaway node the same way.

### Tuning

All knobs are environment variables (read from `/proc/self/environ`; Zig 0.16 dropped
`std.posix.getenv` on no-libc Linux, so non-Linux targets always use the defaults):

| variable | meaning | default |
| --- | --- | --- |
| `ONYX_BENCH_SAMPLES` | independent timed samples per row | 25 |
| `ONYX_BENCH_ITERS` | iterations per sample, CPU-bound rows | 4000 |
| `ONYX_BENCH_ACCEPT_ITERS` | connections per sample, `accept` row | 500 |
| `ONYX_BENCH_ONLY` | run only rows whose name contains this substring | all rows |
| `ONYX_BENCH_JSON` | `1` appends a machine-readable JSON block | off |

```sh
ONYX_BENCH_ONLY=fanout ONYX_BENCH_SAMPLES=51 zig build bench
ONYX_BENCH_JSON=1 zig build bench 2>&1 | sed -n '/^{/,$p' > bench.json
```

The harness prints to **stderr** (`std.debug.print`), so redirect with `2>&1`.

## What each row measures

Five hot-path stages, each isolated so a regression points at one place.

| row | measures | reported |
| --- | --- | --- |
| `inbound-parse` | `proto.irc_line.parseLine` over a mixed client-line corpus (plain, IRCv3-tagged, JOIN, long trailing, many-param MODE) — the per-received-line cost on every byte a client sends. Zero-allocation: `LineView` slices point into the caller's input. | ns/line, MiB/s |
| `outbound-tags/all` | `proto.msgtags.composeOutbound` with all six tags negotiated (server-time, account, msgid, label, batch, bot): building one cap-variant of an outbound line into a caller-provided buffer. | ns/compose |
| `outbound-tags/none` | The same call with an empty cap set — the bare line copy. **`/all` minus `/none` attributes how much of per-recipient framing is tag construction rather than the unavoidable copy.** | ns/compose |
| `fanout-frame/w{1,8,64,512,4096}` | The channel fan-out shape at five widths, modelling the correct discipline: build each distinct cap-variant line **once per message**, then copy the selected variant into each recipient's inline send buffer. | ns/recipient, msgs/sec |
| `fabric-handoff` | The cross-shard delivery fabric round-trip (`daemon.reactor_fabric`): `acquire` a pooled `DeliverBuf` → copy → `sendTo` the target shard's MPMC inbox → `wake` its eventfd → `drainWake` → `drain` a batch → `release`. Batched 64 per wake to match the real cadence (one eventfd write coalesces a burst; one drain clears it). Linux-only. | ns/message, MiB/s |
| `accept` | Loopback connection-accept rate: `socket` → `connect` → `accept4` → close both, ephemeral port. A syscall-bound floor for the accept path with no daemon, no TLS, no io_uring. Linux-only. | accepts/sec |

### The falsifiable property in `fanout-frame`

Each `fanout-frame` row prints `variant_builds_per_msg` in the notes block. It must stay at
the variant count (**4**) at every width, including 4096. If a future change makes it scale
with width, fan-out has become O(N) compose calls instead of O(N) memcpy plus O(V) builds —
and this row will say so instead of the regression shipping silently. That is the single most
useful assertion in the harness.

## Reading the output

Each row reports over `samples` independent timed samples of `ops` operations:

- **`min`** — best observed ns/op: warm cache, no preemption. The cleanest read on the
  *code's* cost, and the column to compare when the machine is not idle.
- **`p50`** — median ns/op, the steady-state number. **Throughput columns are derived from
  p50, never from min.**
- **`p99`** — tail ns/op. A p99 far above p50 means scheduler noise, a cold cache, or a real
  tail problem. Investigate before trusting any delta.

Samples are deliberately short (single-digit milliseconds). A long sample spans many
scheduler quanta, so on a busy box every sample absorbs preemption and the whole distribution
shifts rather than just the tail — measured here as a 2–3x min-to-p50 smear at ~100 ms
samples. With short samples the preemption lands in p99 where it belongs.

**A large min-to-p50 gap is a signal about the machine, not the code.** If `min` and `p50`
differ by more than ~1.5x in any row, the box was contended: trust `min`, and re-capture on an
idle machine before recording a baseline.

Rule of thumb: treat a p50 move under 5% as noise unless it reproduces across two runs.
`tools/bench.sh` runs the harness twice for exactly that reason, which is also the release
plan's acceptance criterion for P0-1 ("a stable baseline on two consecutive runs").

A delta is only meaningful against a baseline captured on the **same machine, kernel, and CPU
governor**. The harness header records arch, OS, CPU count, optimize mode, Zig version, and
the daemon version+commit; `tools/bench.sh` adds CPU model, kernel, governor, and load
average. Never compare a number across two different boxes.

### The `layout` block

After the table the harness prints `@sizeOf` for the structs copied or zero-initialized once
per operation:

```
layout (@sizeOf, bytes) — structs copied or zero-initialized per operation
  proto.irc_line.LineView              2384   returned by value per parsed line
  daemon.deliver_handle.DeliverMsg      456   crosses the shard mailbox by value
  daemon.deliver_handle.DeliverBuf     4120   pooled; 256 slots per shard
```

These are reported, not judged. `LineView` at 2384 bytes is returned **by value** from
`parseLine` on every received line, so it is a direct per-line cost and a candidate for a
later layout pass — but that is a finding for the owning agent, not something this harness
changes.

## Self-verification

Every stage asserts a correctness invariant on its own output: the parse produced the expected
command, the composed line carries its tags, every fan-out copy matches its variant, the
fabric dropped nothing and leaked no pool slot, every connection was accepted. A violated
invariant **exits non-zero** rather than reporting a fast wrong number. A benchmark that
measures broken code is worse than no benchmark.

## What this harness does NOT measure

Named gaps. Do not write a claim about any of these from this harness:

- **TLS and kTLS on/off.** The handshake and record path are not exercised; `outbound-tags`
  and `fanout-frame` measure plaintext framing only.
- **Steady-state RSS per connection.** Needs a live daemon under load — a separate artifact.
- **`num_shards` scaling** and the `world.lockWrite` command-path ceiling. `fabric-handoff`
  measures the handoff cost between two shards *single-threaded*; it says nothing about
  multi-core command throughput. Do not write a "scales with shards" claim from it.
- **End-to-end message round-trip latency** through a real socket and reactor.
- **io_uring submit/complete cost** — deliberately untouched, P0-2.
- **Live-daemon axes** — not this harness. Use `zig build bench-live` /
  `tools/bench.sh --live` (`tools/bench_live.py`). That boots a throwaway
  `onyx-server` on 127.0.0.1 with kernel-assigned ports (never 6667/6680/6697,
  never `orochi.service`), `--check-config` before every boot.

The full P0-1 acceptance criterion in the release plan also names connection-accept rate,
per-message round-trip latency, fan-out throughput, and RSS per connection with TLS/kTLS and
`num_shards` controls. This harness covers accept rate and fan-out framing throughput.
`bench-live` covers register→001 latency, JOIN+PRIVMSG RTT, RSS idle vs N clients, and the
TLS / `num_shards` / `ring_entries`×`cqe_batch` matrix. kTLS is the configured intent
(`txrx`); the cell `note` records whether the kernel actually attached ULP.

## Live-daemon recipe

```sh
zig build bench-live -- --quick
tools/bench.sh --live -o docs/audit/bench-live-0.7.0-rc.1.md
```

Default matrix: plaintext at shards 1 and 2, `ring_entries` 32 vs 128, `cqe_batch`
256 vs 512, plus userspace TLS and kTLS-intent on the default io pair. `--quick`
is one plaintext cell (smoke, not a baseline). A TLS cell that cannot handshake
(for example Python `ssl` vs an Ed25519 bootstrap leaf) is recorded as a failed
cell — never silently skipped. Do not fold `bench-live` into `zig build test`.

## Recording a baseline

```sh
tools/bench.sh -o docs/audit/bench-baseline-0.5.8.md
```

Do it on an idle machine with a known governor, and check the two runs agree before
committing the artifact. The output block carries its own provenance table, so a future reader
can tell whether their machine is comparable.
