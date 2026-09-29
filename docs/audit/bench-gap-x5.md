# GAP-X5 hot path

Every number in the table below was produced by this command and no other:

```sh
zig build bench-gap-x5 -- -o docs/audit/bench-gap-x5.md
```

Bytes per connection is `@sizeOf(ConnState)`, the object stored in the
client table. The slot size adds the generation and freelist word the
table reserves around that object. Fresh `ConnState.init` leaves the
SendQ overflow, the RecvQ overflow, and the session-list cache empty,
so those heaps contribute 0 bytes. This is not RSS per client.

No shrink was applied in this run. The after column is `none`, which
means unmeasured, not a second copy of the before number. The Helix
clients capsule was not edited. A shrink that changes that capsule is
a version bump.

The fan-out row is single-threaded. It builds four cap variants once
per message with `composeOutbound`, then `enqueuePlainFanout` copies
the matching variant into each connection's inline SendQ. That is
`appendToConn` on a plaintext connection. `send_len` is cleared after
each message so the sample stays on the inline path; overflow stayed
empty. Those four composes are inside each message and the elapsed
time is divided by the recipient count, so the width-1 figure
includes all four composes. It is not a multi-shard scaling claim,
and it is not the end-to-end socket RTT from `bench-live`.

## Provenance

| field | value |
| --- | --- |
| version | `0.7.0+077c03dd` |
| commit | `077c03dd` |
| optimize | `ReleaseFast` |
| zig | `0.17.0-dev.1282+c0f9b51d8` |
| arch/os | `x86_64-linux` |
| cpus | 8 |
| captured | 2026-09-29T08:08:57Z |
| host | `eshmaki.me` |
| kernel | Linux 7.1.3-arch2-2 |
| cpu | Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz |
| load avg | 2.96 3.84 4.25 |

## Before any shrink

| quantity | before | after shrink |
| --- | ---: | --- |
| bytes per connection (`ConnState`) | 38080 | none |
| bytes per connection (client-table slot) | 38096 | none |
| `recv_buf` bytes | 4096 | none |
| `line_buf` bytes | 8193 | none |
| `send_buf` bytes | 8192 | none |
| `proxy_buf` bytes | 4096 | none |
| `DeliverBuf` bytes (cross-shard pool slot, not per connection) | 4120 | none |
| clients capsule current / min / max | 5 / 5 / 5 | unchanged |

`DeliverBuf` is named here and was not resized.

## Microseconds per fan-out recipient

| width | samples | msgs/sample | min us/recipient | p50 us/recipient | p99 us/recipient | p50 ns/recipient | after shrink |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | 25 | 4096 | 3.026 | 3.050 | 3.056 | 3049.6 | none |
| 10 | 25 | 409 | 0.328 | 0.330 | 0.332 | 330.1 | none |
| 100 | 25 | 40 | 0.056 | 0.056 | 0.059 | 56.5 | none |
| 1000 | 25 | 4 | 0.031 | 0.031 | 0.036 | 31.0 | none |
| 4096 | 25 | 4 | 0.029 | 0.030 | 0.031 | 29.8 | none |

Blank cells are unmeasured, not zero. `p50 us/recipient` is the median
sample's nanoseconds per recipient divided by 1000.
