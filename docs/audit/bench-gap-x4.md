# GAP-X4 Linux live bench

Every number in the table below was produced by this command and no other:

```sh
zig build bench-live -- --gap-x4 -o docs/audit/bench-gap-x4.md
```

Throwaway `onyx-server` on 127.0.0.1, kernel-assigned ports, `--check-config` before each boot. Not a production service unit.

clients=4  privmsg_samples=16

JOIN p50 is the median time from `JOIN` to numeric 366. PRIVMSG p50 is
the median time from `PRIVMSG` on the first client until the last client
receives that token. RSS idle is before any client; RSS loaded is after
every client has joined.

## Provenance

| field | value |
| --- | --- |
| binary | `/home/kain/onyx-server/.zig-cache/o/32dcb76acf11eb91d2c72ba61a0eadd4/onyx-server-bench-live` |
| commit | `9271e4bf` |
| captured | 2026-09-29T09:57:28+0200 |
| host | eshmaki.me |
| kernel | Linux 7.1.3-arch2-2 |
| cpu | Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz |
| load avg at start | 6.90 4.20 3.39 |

| sqpoll | tls | shards | ring×cqe | register p50 ms | JOIN p50 ms | PRIVMSG p50 ms | RSS idle KiB | RSS loaded KiB | RSS/client KiB | note | error |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| false | off | 1 | 32×256 | 0.48 | 0.36 | 0.16 | 7316 | 12700 | 1346.0 |  |  |
| false | off | 4 | 32×256 | 0.41 | 0.35 | 0.17 | 21444 | 25864 | 1105.0 |  |  |
| false | userspace | 1 | 32×256 | 47.85 | 0.55 | 0.19 | 10568 | 13188 | 655.0 |  |  |
| false | userspace | 4 | 32×256 | 43.30 | 0.46 | 0.20 | 19496 | 24400 | 1226.0 |  |  |
| true | off | 1 | 32×256 | 0.51 | 0.51 | 0.17 | 12480 | 16484 | 1001.0 |  |  |
| true | off | 4 | 32×256 | 1.45 | 0.47 | 0.16 | 19480 | 24228 | 1187.0 |  |  |
| true | userspace | 1 | 32×256 | 44.23 | 0.55 | 0.20 | 12648 | 17140 | 1123.0 |  |  |
| true | userspace | 4 | 32×256 | 46.50 | 1.90 | 0.17 | 19644 | 24152 | 1127.0 |  |  |

RSS/client is (loaded − idle) / N after JOIN. A small or negative
delta means the idle image already dwarfs N clients — do not treat
it as a per-conn floor. A blank timing with an error is an unmeasured
cell, not a zero. TLS `userspace` sets `ktls = "off"`. The kTLS
`txrx` cell, when present, is configured intent only; the note says
whether the kernel attached ULP. `[io] sqpoll` is set without
`defer_taskrun`.

Non-Linux rows are not in this table. This host is Linux, and the
portable reactor cannot execute the same recipe.
