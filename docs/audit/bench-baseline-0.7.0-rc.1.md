# Benchmark baseline — onyx-server 0.7.0-rc.1

Produced by `tools/bench.sh` (`zig build bench`, harness:
`src/substrate/bench.zig`). Release plan P0-1 / wave W1-1.

## Provenance

| field | value |
| --- | --- |
| manifest version | `0.7.0-rc.1` |
| commit | `d638847e` |
| captured | 2026-09-04T07:00:51+02:00 |
| host | eshmaki.me |
| kernel | Linux 7.0.3-arch1-2 |
| cpu | Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz |
| cpu governor | powersave |
| load avg at start | 24.70 21.66 20.71 |
| zig | 0.17.0-dev.1282+c0f9b51d8 |
| runs | 2 consecutive |

Compare deltas ONLY against a baseline captured on this same machine,
kernel, and governor. If `min` and `p50` differ by more than ~1.5x in any
row, the box was contended during capture: trust `min` for code cost and
re-capture on an idle machine before recording a baseline.

## Run 1 of 2

```
onyx-server bench — 0.7 measurement harness (P0-1 baseline)

  version        0.7.0-rc.1+d638847e
  arch/os        x86_64-linux
  cpu count      8
  optimize       ReleaseFast
  zig            0.17.0-dev.1282+c0f9b51d8
  scope          all rows

  Throughput is derived from p50, never from min. Compare only against a
  baseline captured on THIS machine, kernel, and CPU governor.

row                             ops    samp    min ns/op    p50 ns/op    p99 ns/op  ops/sec (p50) MiB/s (p50)
------------------------------------------------------------------------------------------------------------
inbound-parse                 24000      25       285.90       289.42       374.93        3455219       408.6
outbound-tags/all              4000      25      1563.26      1567.35      1759.13         638021           -
outbound-tags/none             4000      25        18.44        18.48        19.94       54117679           -
fanout-frame/w1                4000      25      3359.27      3379.96      3716.41         295862           -
fanout-frame/w8                4000      25       427.69       429.50       435.81        2328305           -
fanout-frame/w64               3968      25        59.38        59.62        60.43       16771914           -
fanout-frame/w512              3584      25        13.41        13.48        14.78       74181397           -
fanout-frame/w4096             4096      25         8.68         8.73         9.85      114512567           -
fabric-handoff                 3968      25       115.68       117.89       131.80        8482747       582.5
accept                          500      25     28135.56     28519.49     31215.22          35064           -

notes
  inbound-parse          zero-alloc view parse
  outbound-tags/all      6 tags: time, account, msgid, label, batch, bot
  outbound-tags/none     no caps: the bare line-copy floor (subtract to attribute tag cost)
  fanout-frame/w1        variant_builds_per_msg=4 (must not scale with width)
  fanout-frame/w8        variant_builds_per_msg=4 (must not scale with width)
  fanout-frame/w64       variant_builds_per_msg=4 (must not scale with width)
  fanout-frame/w512      variant_builds_per_msg=4 (must not scale with width)
  fanout-frame/w4096     variant_builds_per_msg=4 (must not scale with width)
  fabric-handoff         batch=64 per wake, 0 drops, 0 pool leaks
  accept                 loopback, ephemeral port, no TLS, no io_uring

layout (@sizeOf, bytes) — structs copied or zero-initialized per operation
  proto.irc_line.LineView              2384   returned by value per parsed line
  daemon.deliver_handle.DeliverMsg      456   crosses the shard mailbox by value
  daemon.deliver_handle.DeliverBuf     4120   pooled; 256 slots per shard
```

## Run 2 of 2

```
onyx-server bench — 0.7 measurement harness (P0-1 baseline)

  version        0.7.0-rc.1+d638847e
  arch/os        x86_64-linux
  cpu count      8
  optimize       ReleaseFast
  zig            0.17.0-dev.1282+c0f9b51d8
  scope          all rows

  Throughput is derived from p50, never from min. Compare only against a
  baseline captured on THIS machine, kernel, and CPU governor.

row                             ops    samp    min ns/op    p50 ns/op    p99 ns/op  ops/sec (p50) MiB/s (p50)
------------------------------------------------------------------------------------------------------------
inbound-parse                 24000      25       285.51       299.88       694.20        3334634       394.3
outbound-tags/all              4000      25      1555.59      1604.67      8248.18         623182           -
outbound-tags/none             4000      25        18.37        18.40       107.12       54343396           -
fanout-frame/w1                4000      25      3306.92      3511.28     13202.81         284796           -
fanout-frame/w8                4000      25       272.38       287.53       442.11        3477856           -
fanout-frame/w64               3968      25        37.05        37.15        45.09       26917937           -
fanout-frame/w512              3584      25         8.99         9.03        14.53      110716382           -
fanout-frame/w4096             4096      25         7.26         7.32         8.17      136651765           -
fabric-handoff                 3968      25        88.17        90.68       111.25       11027859       757.2
accept                          500      25     21599.09     25151.81     31783.05          39759           -

notes
  inbound-parse          zero-alloc view parse
  outbound-tags/all      6 tags: time, account, msgid, label, batch, bot
  outbound-tags/none     no caps: the bare line-copy floor (subtract to attribute tag cost)
  fanout-frame/w1        variant_builds_per_msg=4 (must not scale with width)
  fanout-frame/w8        variant_builds_per_msg=4 (must not scale with width)
  fanout-frame/w64       variant_builds_per_msg=4 (must not scale with width)
  fanout-frame/w512      variant_builds_per_msg=4 (must not scale with width)
  fanout-frame/w4096     variant_builds_per_msg=4 (must not scale with width)
  fabric-handoff         batch=64 per wake, 0 drops, 0 pool leaks
  accept                 loopback, ephemeral port, no TLS, no io_uring

layout (@sizeOf, bytes) — structs copied or zero-initialized per operation
  proto.irc_line.LineView              2384   returned by value per parsed line
  daemon.deliver_handle.DeliverMsg      456   crosses the shard mailbox by value
  daemon.deliver_handle.DeliverBuf     4120   pooled; 256 slots per shard
```

## Interpretation

See `docs/dev/benchmarks.md` for what each row measures, what it
deliberately does NOT measure (TLS/kTLS, RSS per connection, `num_shards`
scaling, end-to-end round-trip, io_uring submit cost), and how to read the
min/p50/p99 columns.

This capture is a **first harness artifact**, not a stable P0-2 before/after
baseline. Load average at start was 24.70 and several p50s moved more than
5% between the two consecutive runs (fan-out widths, fabric-handoff,
accept). Trust `min` for code cost; re-capture on an idle machine (same
kernel and governor) before using these numbers as a comparison floor.
Live-daemon axes (TLS mode, shard count, `ring_entries` × `cqe_batch`)
remain unmeasured.
