# Portable TLS cipher-policy experiment

The matched local workload observed higher throughput and lower CPU cost with
ChaCha preferred when the compiled AES backend is software. Accelerated builds
retain AES preference, and AES remains available when ChaCha is not offered.
This is evidence for a source change, not release or deployment acceptance.

The original single-buffer allocation draft is excluded: its earlier matched
study regressed throughput and remains unpromoted. Both artifacts here retain
the original TLS sealing implementation. They differ only in
`src/crypto/tls_server.zig`, including the separately reproduced HRR/PSK exact
suite fix and the cipher-policy tests. All 1,218 captured source/build/tool
inputs were verified before measurement.

## Observations

Three counterbalanced pairs (AB, BA, AB), plus two correctness pilots, used four
persistent TLS 1.3 clients, one channel and reactor, 128-byte payloads, credit
window 64, SQPOLL disabled and userspace TLS. All eight cases passed. The six
full cases authored 400,896 messages and delivered exactly 1,202,688 copies.

| Continuous metric | Baseline median (range) | Candidate median (range) | Median change |
| --- | --- | --- | --- |
| Deliveries/s | 8,365.622 (8,188.998–9,518.219) | 9,998.765 (9,993.815–10,236.913) | +19.52% |
| Daemon CPU per delivery | 97.504 µs (86.517–97.555 µs) | 78.430 µs (78.176–79.956 µs) | -19.56% |
| p50 latency | 62.476 ms (56.851–67.262 ms) | 51.416 ms (50.392–54.374 ms) | -17.70% |
| p99 latency | 115.300 ms (96.673–117.110 ms) | 95.979 ms (94.287–100.954 ms) | -16.76% |

Every paired run improved throughput (approximately 5.0% to 25.0%), CPU cost per
delivery (9.6% to 19.6% lower), and p99 latency (2.5% to 16.8% lower). Burst
median daemon CPU fell from 0.34 to 0.28 seconds; idle counters recorded zero
CPU ticks in both variants at 10 ms tick resolution; this does not prove zero
idle cost. Driver CPU was measured separately.

A separate correctness pilot observed all four default-offer baseline clients
negotiating AES-128-GCM and all four candidate clients negotiating ChaCha20-Poly1305. TLS version and workload were unchanged. The candidate probe reused
the baseline probe's description string; `cipher-probe-policy/scope-note.json`
clarifies that metadata wording and binds the raw receipt and candidate digest.

## Source and artifact evidence

Both artifacts use the pinned Zig compiler, `safe`, `x86_64-linux-musl` and
`-Dcpu=x86_64`. Native host: Alpine 3.24.2, Linux 6.18.55, Xeon E5-2690 v2.
No controlled compiler or other test job ran during the study. Existing services
remained active; CPU affinity and frequency were not isolated. Three pairs do
not establish statistical precision, global capacity, mesh performance or a
universal speedup. In particular, the baseline varied considerably between
pairs. The observations above apply to this workload and these captured images.

- Baseline SHA-256: `f977556e3cdae8749f2254a795525e61385c4ab286ea3b69f8b76b8d1d1364df`.
- Candidate SHA-256: `ef4c7f773829734cd015a02c2dac1cbcbf676f7d355f571ab8db81a8af2fd6f9`.
- Build receipts: `before-build.json` and `suite-policy-artifact-build.json`.
- Artifact metadata: `before-artifact.json` and `suite-policy-artifact.json`.
- Raw cases, commands, summaries and decision: `study-suite-policy-01/`.
- Driver: `matched_study_v3.py`, with unchanged helper hashes recorded per study.

These paths are relative to `.zig-cache/wave-8/throughput-terra/`. Independent
review recomputed artifact/report hashes, manifest differences, totals and
paired results, and approved source integration. Full combined release gates
and deployment acceptance remain separate requirements. No live daemon or configuration was changed by
this experiment.
