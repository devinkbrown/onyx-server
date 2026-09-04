# Staged 0.5.8 → 0.7.0-rc.1 Helix rehearsal

Throwaway loopback only. Not `orochi.service`. Kernel-assigned ports via
`tools/upgrade_smoke.py`. Predecessor and successor are the musl artifacts in
`dist/` (statically linked, stripped).

## Binaries

| role | path | banner |
| --- | --- | --- |
| predecessor | `dist/onyx-server-0.5.8-x86_64-linux-musl` | `0.5.8+ea249b2` |
| successor | `dist/onyx-server-0.7.0-rc.1-x86_64-linux-musl` | `0.7.0-rc.1+1e4215a0` |

0.5.8's compiled-in current capability line is byte-identical to 0.7's first
advertised line (`sessions-v4` included). `hasUpgradeCapabilityLine` on the
predecessor therefore matches. The `predecessor_v4` bridge line is the same
token today; it exists so a later 0.7 capability bump can still admit 0.5.8.

## Runs (2026-09-04, eshmaki.me)

Both runs: 2 shards, 8 filler clients, live TLS + mid-frame wss, bouncer token,
`+i` / MONITOR / SILENCE, WHOIS + NAMES after swap. Same PID across execve.

| trigger | command | result |
| --- | --- | --- |
| `UPGRADE` | `python3 tools/upgrade_smoke.py dist/onyx-server-0.5.8-x86_64-linux-musl dist/onyx-server-0.7.0-rc.1-x86_64-linux-musl` | **ALL CHECKS PASSED** (~7.2s). Seals `{0: 5, 1: 8}`. |
| `SIGUSR2` | `ONYX_HELIX_TRIGGER=usr2` + the same two binaries | **ALL CHECKS PASSED** (~10.4s). Seals `{0: 6, 1: 6}`. |

Zero dropped sessions on every held socket (plain, TLS, wss mid-frame, all
fillers). Reclaim token unchanged. Fresh client registered after the swap.

This is not a production USR2 of `orochi.service`.
