# Benchmarking Onyx Server

Benchmarks measure a captured implementation on a particular machine. They do
not replace correctness tests or live acceptance. Source:
[offline harness](../../src/substrate/bench.zig),
[wrapper](../../tools/bench.sh), [live harness](../../tools/bench_live.py), and
[build graph](../../build.zig).

## Choose the measurement

| Question | Harness | What the result can establish |
|---|---|---|
| Parser, outbound tag composition or framing cost | `zig build bench` | CPU/memory cost of isolated operations on its fixed corpus. |
| Cross-shard handoff or loopback accept floor | `zig build bench` | Harness-local syscall/fabric cost; Linux-only rows do not prove another platform. |
| Throwaway daemon latency and RSS | `zig build bench-live` | Its selected TLS/shard/ring cells, not fleet capacity. |
| Controlled idle/burst/continuous SQPOLL comparison | `tools/bench_live.py --sqpoll-phases` | Exact-delivery and CPU windows for a pinned artifact/profile. |
| Full test-suite latency | Source-bound full test gate | Its complete inventory, command, host, source, binary and logs; not general daemon throughput. |
| Constant-time behavior | `zig build ct-check` | Statistical timing observations under its documented controls, separate from deterministic CI. |

## Offline examples

```sh
zig build bench
# Two consecutive measurements with machine provenance:
tools/bench.sh --runs 2 -o .zig-cache/benchmark-baseline.md
# A quick harness smoke, not a publishable throughput baseline:
tools/bench.sh --quick
# Select a smaller question; Linux environment tuning:
ONYX_BENCH_ONLY=fanout ONYX_BENCH_SAMPLES=51 zig build bench
```

The build step compiles an optimized standalone harness; it does not start the
production daemon. Output uses stderr, so capture both streams when saving it.
The wrapper adds CPU, kernel, governor, load, compiler and revision information.
The harness is separate from deterministic `test` and `all-checks` gates.

| Linux environment setting | Default | Meaning |
|---|---:|---|
| `ONYX_BENCH_SAMPLES` | 25 | Timed samples per row. |
| `ONYX_BENCH_ITERS` | 4000 | Iterations per sample for CPU rows. |
| `ONYX_BENCH_ACCEPT_ITERS` | 500 | Connections per accept sample. |
| `ONYX_BENCH_ONLY` | unset | Substring selection of row names. |
| `ONYX_BENCH_JSON` | unset | `1` appends machine-readable output. |

The environment is read through the Linux mechanism documented in the harness;
other targets need their own validated invocation rather than assumed tuning.

Rows separate inbound parsing, outbound tags with/without negotiated fields,
fanout framing, cross-shard fabric handoff and loopback accept. Framing is not
TLS record encryption or socket delivery. Compare variant-build counts across
fanout widths: building one frame per recipient is a different algorithm from
building each capability variant once and copying it to its recipients.

## Private live examples

```sh
zig build bench-live -- --quick
tools/bench.sh --live --quick
```

These start temporary loopback daemons, preflight generated config and avoid
production service units and the documented forbidden listener ports. The
quick path checks the harness; its small cell is not a scale claim. Use a
captured artifact for a controlled profile:

```sh
python3 -B tools/bench_live.py --bin /absolute/path/to/captured-onyx-server \
  --sqpoll-phases --phase-pilot --repetitions 1 --sqpoll-modes 10 \
  --expected-sha256 <verified-artifact-sha256> \
  --phase-json .zig-cache/sqpoll-pilot.json
```

Replace the SHA placeholder with the actual recorded artifact digest. The
retained phase profile uses pinned TLS, persistent clients, exact ordered
fanout receipts and distinct idle/burst/continuous CPU windows, including
verified SQPOLL workers. A phase pilot proves the reduced profile's correctness,
not throughput or a general SQPOLL win. See the tool's `--help` for profile axes.

## Interpret and publish carefully

Record source revision and dirty state, compiler/archive identity, target,
optimization, artifact hash, host/kernel, CPU/governor, contention, profile,
iteration/sample counts and raw output. Use the same machine and controls for
before/after comparisons and repeat measurements.

`min`, `p50` and `p99` describe different parts of the sampled operation-cost
distribution. The harness derives throughput from the median. A large gap can
reflect scheduling and cache effects; it does not identify the cause by itself.
Sampled operation-cost percentiles are not necessarily end-user message-latency
percentiles. Layout sizes printed by the harness are observations, not proof
of a memory bug.

Keep failures and missing measurements visible. Verify exact deliveries,
cleanup and absence of overlapping benchmark processes before interpreting
performance. Report regressions as well as gains and separate observed data
from inference. Shared-host comparisons must say so, as the
[full-suite timing report](../audit/release-and-test-speed-2026-11-03.md) does.
