# SQPOLL idle-window measurements

The production backend is `src/daemon/ringlane.zig`; the similarly named
substrate ring is a prototype. The production constructor previously fixed
the SQPOLL idle window at 1000 ms. Every setup-ladder attempt now receives an
explicit window through `init_params`, including fallbacks without CQSIZE.
Submission and the existing NEED_WAKEUP/SQ_WAKEUP path are unchanged.

SQPOLL remains **disabled by default**. An enabled worker now has a balanced
default of **10 ms**, with `io.sqpoll_idle_ms = 1000` available for the former
latency-oriented policy. The setting accepts integers from 1 through 60000.
Zero is refused rather than acquiring an implicit kernel default. These
settings apply when new rings are created.

## Controlled evidence

The isolated worker used production Ringlane on Linux kernel
`6.18.55-0-lts`, x86_64, Zig 0.17.0. It compared SQPOLL off, 1000 ms and 10 ms;
one and four rings; 250-ms bursts and continuous submission; batches of 32 and
256; and three alternating repetitions. All **72 cells** passed with exact,
unique CQE IDs and zero results. The run verified **2,736,560,512 CQEs** and
**120 sleeping-worker wakeups**.

CPU accounting includes the worker's user threads and its verified kernel
SQPOLL workers. READY/GO/RESULT/ACK keeps those tasks alive through both
snapshots. Counters are tick-quantized; zero means below measurement resolution.
Driver CPU is excluded. Host scheduling and load can affect these measurements.

Four-ring medians:

| Workload | 1000 ms | 10 ms |
| --- | ---: | ---: |
| Burst, batch 32: CPU core equivalents | 3.987 | 0.163 |
| Burst, batch 256: CPU core equivalents | 3.989 | 0.173 |
| Burst, batch 32: median completion latency | 10.49 μs | 41.36 μs |
| Burst, batch 32: p99 completion latency | 21.37 μs | 70.83 μs |
| Burst, batch 256: median completion latency | 27.47 μs | 57.17 μs |
| Burst, batch 256: p99 completion latency | 81.52 μs | 103.89 μs |
| Continuous, batch 32: million NOPs/second | 21.920 | 21.366 |
| Continuous, batch 256: million NOPs/second | 45.287 | 45.001 |

The short window reduced CPU about 96% in these burst cells, with about 30 μs
additional median latency. Continuous medians were 2.53% and 0.63% lower.
SQPOLL-off won this NOP model's throughput/CPU comparison and remains the
ordinary default. This supports the short window for bursty opt-in polling;
it does not prove a universal IRC, mesh, authentication or media throughput gain.

## Reproduction and acceptance

Worker and sampler: `tools/bench_sqpoll.zig`, `tools/bench_sqpoll.py`.
Raw evidence: `.zig-cache/sqpoll/matrix-3000ms.json` and its JSONL log.
Measured binary SHA-256:
`1341ae9b0fa390333b132935108805d84ceefdee6ac704e65b6bf3a7894e66ba`.
The measured 1000-ms-default source is retained as
`.zig-cache/sqpoll/ringlane-measured-af80b432.zig`; every matrix mode supplied
an explicit value, so changing the default does not alter the measured cells.

The constructor/explicit-profile focused gates passed **85/85 in Debug and
ReleaseSafe**. The later default and shared configuration projection passed 135 tests with
seven platform skips in Debug and fresh review. The subsequent combined ReleaseSafe gate passed 699 tests with 34
platform/root skips and zero failures; its named set includes these cases
(`.zig-cache/wave-5/combined-security-safe.json`). No deployed process or configuration
was changed by this experiment. Native daemon workloads and release gates
remain separate acceptance steps.


## Next native daemon comparison

The next bounded slice extends `tools/bench_live.py`, reusing private bundle
provisioning and pinned TLS trust from `setup_tls_smoke.py` and CPU custody
checks from `bench_sqpoll.py`. It uses one captured image, TLS 1.3 with kTLS
off, four persistent clients, one channel and one shard. Explicit SQPOLL modes
are off, 10 ms and 1000 ms, with three alternating repetitions. Configurations,
payloads, queue bounds and sampling intervals stay equal across modes.

After drained warmup, measure ten seconds idle; forty 250-ms bursts with eight
messages per sender per burst; and 16,384 continuous messages per sender with a
bounded outstanding window. Without echo-message, expected authored/delivered
counts are 1,280/3,840 and 65,536/196,608 respectively. Persistent CRLF readers
must validate every sender/sequence at each recipient, in order, without
missing or duplicate deliveries. Complete ledgers and unique PING/PONG
barriers close each phase; readers keep checking late duplicates through final
drain. Substring receipt checks cannot establish these properties.

CPU windows start after warmup and end after delivery/barrier drain, before
teardown. Include verified daemon and SQPOLL tasks, checking start identities
at both snapshots; missing task coverage invalidates the cell. Record driver
CPU separately, delivered throughput, CPU per delivery and latency. Metrics
refresh outside those windows: message counters include control lines and
output-byte counters mean queued bytes. Client ledgers prove delivery.

Four-shard acceptance is a subsequent profile requiring witnessed accepts on
every shard while all clients remain connected. Four random clients alone do
not prove that distribution. These are planned checks, not measured daemon
results or an accepted throughput claim.


## Native correctness pilot

The retained profile passed its first small 10-ms native pilot on Alpine Linux
3.24.2, x86_64, kernel `6.18.55-0-lts`. Four pinned-TLS 1.3 clients produced
exactly 24 burst and 192 continuous recipient deliveries. Every phase records
`cpu_discovery_verified=true`, including fresh discovery of external SQ workers
outside the CPU window. An earlier pilot used an unsupported `metrics.port`
setting and failed; changing it to the actual `metrics.listen` field with
loopback binding corrected the fixture. Both outcomes remain retained.

The successful gate uses explicit runtime source dependencies and captured
image `80c8152491bd…92d20`, with bytecode writes disabled; its inputs remained
unchanged. Receipt and report:
`.zig-cache/wave-6/live-benchmark/pilot-metrics-fixed-gate.json` and
`pilot-metrics-fixed.json`. The broad first gate recorded changed inputs; its
exact change cause was not established. No cache-only explanation is asserted.

This is a Debug-image correctness pilot, not a throughput baseline. An explicit
ReleaseSafe x86_64-linux-musl baseline-CPU candidate is being built before the
full comparison. `daemon_cpu_s` in the profile is total associated daemon plus
SQ-worker CPU; `sq_cpu_s` is its subset and must not be added again. Driver CPU
is separate. Zero CPU ticks mean below the sampling resolution.

The optimized native comparison is now available in the
[chat benchmark report](live-chat-sqpoll-benchmark-2026-10-26.md): nine cells and
1,804,032 exact deliveries. Its sustained-rate tradeoff differs from the NOP
model; the reports retain their distinct workloads and limits.
