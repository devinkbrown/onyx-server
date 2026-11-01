# Native chat SQPOLL comparison

2026-10-26 · measured local candidate · one shard, four clients

All **nine cells passed**, with **601,344 authored messages and 1,804,032 exact
recipient deliveries**. Three alternating repetitions compared SQPOLL off,
10 ms and 1000 ms. Every phase completed its ordered recipient ledgers,
unique barriers and fresh task-discovery checks; no missing or duplicate
receipts were accepted. This is an end-to-end TLS chat profile, separate from
[the low-level NOP experiment](sqpoll-idle-benchmark-2026-10-26.md).

## Artifact and workload

The captured image is a Zig 0.17.0 **ReleaseSafe** build for
`x86_64-linux-musl`, with CPU baseline `x86_64`. SHA-256:
`5850a26f80b9966e72dccedca2e1d2e6f1c267118bfeb56c87c635f7d06e5a5e`.
It is 14,404,200 bytes, built from server source
`af14549bfadebcb49e603fc4f1ee95dff53629dda980e34c176ddd8346a689e6`.
Later media-pump edits and test additions are outside that image. It has not
been deployed.

The native environment was Alpine Linux 3.24.2, kernel `6.18.55-0-lts`, x86_64.
A subsequent hardware observation identified Intel Xeon E5-2690 v2 at 3.00 GHz,
40 logical CPUs and affinity allowing all 40. CPU placement, frequency and
other host load were not isolated. Each cell retains load observations.

Four persistent clients use private-CA and hostname-verified TLS 1.3, with
kTLS explicitly off. All send and receive in one channel on one shard.
Ring entries are 512, CQE batch 256, payload 128 bytes and credit window 64.
After drained warmup, phases are ten seconds idle; forty 250-ms ticks with
eight messages per client per tick; and 16,384 continuous messages per client.
Without echo-message, expected burst and continuous deliveries are 3,840 and
196,608 per cell. Counter freshness is checked outside CPU windows;
queued-byte counters are not used as proof of delivery.

## Three-repetition medians

CPU columns include the daemon's user threads and its verified kernel SQ
worker. `sq_cpu_s` is a subset of reported `daemon_cpu_s`; adding them would
double-count. Driver CPU is measured separately. Tick resolution is 10 ms;
zero means below measurement resolution.

| SQPOLL | Idle cores | Burst cores | Continuous cores | Continuous deliveries/s | CPU µs/delivery |
| --- | ---: | ---: | ---: | ---: | ---: |
| off | 0.000 | 0.044 | 0.825 | 8,510 | 96.94 |
| 10 ms | 0.006 | 0.151 | 1.795 | 8,716 | 205.89 |
| 1000 ms | 0.500 | 1.028 | 1.812 | 9,247 | 194.91 |

| SQPOLL | Burst p50 ms | Burst p99 ms | Continuous p50 ms | Continuous p99 ms |
| --- | ---: | ---: | ---: | ---: |
| off | 11.94 | 50.76 | 51.08 | 111.66 |
| 10 ms | 9.71 | 51.68 | 61.77 | 113.18 |
| 1000 ms | 9.50 | 50.60 | 60.68 | 107.50 |

Continuous driver use was about 0.38–0.39 core. Continuous delivery-rate ranges
across the three repetitions were off: 8,188–9,356; 10 ms: 8,371–9,388; 1000 ms: 9,114–9,385.

The 10-ms setting used **98.8% less idle CPU and 85.3% less burst CPU** than
1000 ms in this profile. The paced burst rate was essentially equal by design.
Its continuous median delivery rate was **5.74% lower** than 1000 ms. Sample
ranges overlap; this run does not establish a causal explanation or statistical
significance for that sustained difference. The proposed no-unexplained-5%
regression budget therefore remains open for this comparison.

SQPOLL off remains the ordinary default and had the lowest CPU cost per
continuous delivery here. A 10-ms opt-in window is supported as a burst-CPU
tradeoff; it is not a universal throughput optimization. The 1000-ms setting
remains explicit. These observations do not establish multi-shard capacity,
mesh fanout, voice/video quality, allocation count, p95 latency or production
service readiness. Negotiated cipher details were not retained in this report;
future profiling should record them before attributing crypto cost.

## Reproduction and retained evidence

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/bench_live.py \
  --sqpoll-phases --repetitions 3 --sqpoll-modes 0 10 1000 \
  --expected-sha256 <full-artifact-sha256> \
  --phase-json /private/output.json --bin /absolute/captured/onyx-server
```

Zero encodes off. `--phase-pilot` selects a smaller correctness-only profile.
The harness has 21 offline checks covering framing, late mixed-case duplicates,
TLS refusal, barriers and discovery of a newly created external SQ worker.
Fresh reviews approved those boundaries before native execution. The first
native pilot exposed an unsupported generated `metrics.port` key; the corrected
fixture uses `metrics.listen` and explicit loopback binding.

Retained files under `.zig-cache/wave-6/` include `optimized-musl-build.json`
and `optimized-musl-artifact.json`. Under `live-benchmark/`:

- `full-matrix-gate.{json,log}`: successful 447.583-s gate, unchanged selected inputs;
- `full-matrix.json` and `full-summary.json`: raw per-cell data and medians;
- `optimized-pilot-zero-gate.json`: successful all-three-mode correctness pilot;
- `native-environment.json` and `hardware-observed-after-run.json`: observation scope;
- `driver-source-19e0ecca/` and `driver-source-manifest.json`: exact runtime driver sources and hashes.

The driver SHA-256 is
`19e0ecca35a555090707cc9bdf5a5adb4fa328eeabddb9acd1a45460319dfc49`.
The build and measurement used no production configuration or service changes.


## Reporting improvements after this measurement

The 2026-10-29 harness update adds p95 latency using the existing nearest-rank
calculation and captures each client's actual negotiated TLS version and cipher
name. Cell summaries distinguish uniform, mixed, partial and unknown observations,
including failed cells. These fields expose no certificate or key material.
Delivery accounting, barriers, timing windows and certificate validation remain
unchanged. All 24 offline benchmark tests passed, and independent review approved
the two-file tool delta. Receipt: `.zig-cache/wave-48/offline-v1.json`; guarded
integration: `.zig-cache/wave-48/actual-integration.json`.

This update does not add missing fields to historical results or establish a new
throughput baseline. New comparisons must capture the new harness and selected
daemon hashes, then repeat equivalent workload cells.

A one-cell native correctness pilot subsequently passed using that captured
`5850a26f…` image and the updated harness: four verified TLS 1.3 clients negotiated
`TLS_AES_128_GCM_SHA256`; burst and continuous phases delivered exactly 24 and
192 receipts, with p95 between p50 and p99 and idle latency absent. Input hashes
remained unchanged and the supervisor finished with no owned processes. Evidence:
`.zig-cache/wave-48/native-reporting-pilot-v1.json` and
`native-reporting-pilot-data-v1.json`. This reduced pilot validates reporting and
exact delivery, not current-daemon acceptance or a capacity/performance baseline.
