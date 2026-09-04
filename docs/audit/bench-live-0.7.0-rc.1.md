# Live-daemon bench — P0-1 remaining axes

Throwaway `onyx-server` on 127.0.0.1, kernel-assigned ports, `--check-config` before each boot. Not `orochi.service`.

clients=8  privmsg_samples=16

## Provenance

| field | value |
| --- | --- |
| binary | `/home/kain/onyx-server/.zig-cache/o/3286446c78aa7282fb2b704c1ad5723e/onyx-server-bench-live` |
| commit | `0fea02b9` (dirty tree) |
| captured | 2026-09-04T12:23:03+0200 |
| host | eshmaki.me |
| kernel | Linux 7.0.3-arch1-2 |
| cpu | Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz |
| load avg at start | 4.70 7.12 6.55 |

| tls | shards | ring×cqe | register p50 ms | PRIVMSG p50 ms | RSS idle KiB | RSS/client KiB | note | error |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| off | 1 | 32×256 | 0.25 | 0.10 | 9720 | 353.5 |  |  |
| off | 2 | 32×256 | 0.30 | 0.10 | 16332 | 524.0 |  |  |
| off | 1 | 128×256 | 0.29 | 0.09 | 10768 | 222.5 |  |  |
| off | 1 | 32×512 | 0.29 | 0.17 | 10632 | 230.0 |  |  |
| userspace | 1 | 32×256 | 42.54 | 0.16 | 10776 | 272.5 |  |  |
| ktls | 1 | 32×256 | 42.56 | 0.19 | 14624 | 236.0 | ktls-active |  |

RSS/client is (loaded − idle) / N after JOIN. A small or negative
delta means the idle image already dwarfs N clients — do not treat
it as a per-conn floor. kTLS is the configured intent (`txrx`);
the kernel may keep the path in userspace if ULP is absent.
