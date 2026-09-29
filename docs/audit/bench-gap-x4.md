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

This command writes the Linux rows only. FreeBSD rows are in the next
section, under the command that produced them. OpenBSD and Windows were
not measured. SQPOLL is Linux io_uring. The portable reactor does not
serve a TLS listener. kTLS `txrx` and `defer_taskrun` stayed off.

## FreeBSD kqueue

The guest command, run on the FreeBSD guest after the host builds below,
produced every number in this section:

```sh
zig build -Dtarget=x86_64-freebsd -Doptimize=ReleaseFast
zig build-exe -target x86_64-freebsd -OReleaseFast -femit-bin=bench_x4_portable tools/bench_x4_portable.zig
# on the guest, ReleaseFast binary stamped 0.7.0+d033020a
/tmp/bench_x4_portable /tmp/onyx-server-x4
```

Same client counts as the Linux table: 4 clients, 16 PRIVMSG samples,
`#bench`, numeric 001, numeric 366. Plaintext only. `sqpoll = false` in
the booted config. The portable reactor is one kqueue, so `num_shards`
does not add a poller and `ring_entries` is not a queue depth. The guest
client sets `TCP_NODELAY` because FreeBSD otherwise holds the next small
PRIVMSG until delayed ACK; the daemon does not echo PRIVMSG to the
sender. The accepted socket sets `TCP_NODELAY` as well (`d033020a`).
SQPOLL rows are unmeasured: that option is Linux io_uring. TLS rows are
unmeasured: this reactor does not serve a TLS listener. A blank timing
with an error is an unmeasured cell, not a zero.

## Provenance

| field | value |
| --- | --- |
| binary | guest `/tmp/onyx-server-x4`, ReleaseFast, banner `Onyx Server 0.7.0+d033020a` |
| commit | `d033020a` |
| captured | 2026-09-29T21:11:42+0000 |
| guest | FreeBSD 14.5-RELEASE-p1 amd64 |
| cpu | Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz |
| load avg at start | 0.23 0.26 0.25 |
| listen | `127.0.0.1` kqueue, kernel-assigned ports |

| sqpoll | tls | shards | ring×cqe | register p50 ms | JOIN p50 ms | PRIVMSG p50 ms | RSS idle KiB | RSS loaded KiB | RSS/client KiB | note | error |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| false | off | 1 | 32×256 | 0.09 | 0.04 | 0.03 | 5696 | 5892 | 49.0 | kqueue one poller; ring_entries is not a queue depth; client and server TCP_NODELAY |  |
| false | off | 4 | 32×256 | 0.09 | 0.04 | 0.03 | 5696 | 5896 | 50.0 | kqueue one poller; num_shards does not add a poller; ring_entries is not a queue depth; client and server TCP_NODELAY |  |
| false | userspace | 1 |  |  |  |  |  |  |  |  | portable reactor does not serve a TLS listener |
| false | userspace | 4 |  |  |  |  |  |  |  |  | portable reactor does not serve a TLS listener |
| true | off | 1 |  |  |  |  |  |  |  |  | SQPOLL is Linux io_uring; this reactor is kqueue |
| true | off | 4 |  |  |  |  |  |  |  |  | SQPOLL is Linux io_uring; this reactor is kqueue |
| true | userspace | 1 |  |  |  |  |  |  |  |  | SQPOLL is Linux io_uring; this reactor is kqueue |
| true | userspace | 4 |  |  |  |  |  |  |  |  | SQPOLL is Linux io_uring; this reactor is kqueue |

The same guest command a second time exited 0. Register p50 stayed 0.09 ms
and PRIVMSG p50 stayed 0.03 ms. JOIN p50 was 0.04 ms for one shard and
0.05 ms for four. RSS idle/loaded was 5704/5896 KiB (one shard, 48.0
KiB/client) and 5688/5888 KiB (four shards, 50.0 KiB/client).

OpenBSD and Windows did not run this recipe. Those rows are not in this
file.
