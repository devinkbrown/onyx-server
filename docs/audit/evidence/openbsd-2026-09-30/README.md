<!-- SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com> -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# OpenBSD port evidence

Local OpenBSD 7.9 GENERIC.MP guest, x86_64, two virtual CPUs and 2 GiB RAM.
Compiler: Zig 0.17.0-dev.1282+c0f9b51d8. No production deployment or push.
Earlier plaintext/minimal-runtime logs are historical component evidence.
The expanded native run exposed six failures, now repaired. Consolidated full
Linux and native Debug/ReleaseSafe gates pass. Both final pinned native artifacts
pass secured session, partition/rejoin, sequential Helix and cold-authentication
acceptance. Earlier records retain their intermediate artifact pins.

| Gate | Durable record |
|---|---|
| Final native unfiltered Debug and ReleaseSafe, module 8584/8732 with 148 skips, CLI 51/53 with 2 skips, daemon 0, zero failures | `openbsd-unfiltered-consolidated-debug-raw.log`, `openbsd-unfiltered-consolidated-rs-raw.log`, `openbsd-unfiltered-consolidated-debug-cli-daemon.log`, `openbsd-unfiltered-consolidated-rs-cli-daemon.log` |
| Final consolidated Linux full Debug and ReleaseSafe, each 8761 passed / 8785 total, 24 skipped, zero failed | `full-port-consolidated-linux-debug.log`, `full-port-consolidated-linux-rs.log` |
| Native Debug and ReleaseSafe secured three-host sessions, actual PF cut/rejoin, three upgrades, fifth resume, cold WAL authentication; each 51 accepted events / 243 recipient deliveries | `openbsd-native-session-consolidated-debug-final.log`, `openbsd-native-session-consolidated-rs-final.log` |
| Final ReleaseSafe 40 original IPv4/IPv6 plaintext/TLS 1.2/TLS 1.3/WSS clients, rejected missing-key candidate and two successful upgrades | `native-consolidated-final-rs-all-transports-rejection-helix.log`, `native-consolidated-final-rs-daemon.log` |
| Final pinned ReleaseSafe confined plugin boot and authenticated REHASH: replacement command, old 421, original TLS PONG | `native-consolidated-final-rs-plugin-acceptance.log`, `native-plugin-daemon-9e083f445abc.log` |
| Native worker protocol Debug/ReleaseSafe: actual SMTP STARTTLS, WebPush payload/VAPID validation, 201 and 410 | `openbsd-worker-protocol-stack-fixed-native-debug.log`, `openbsd-worker-protocol-stack-fixed-native-release-safe.log` |
| Native history seal synchronization, allocation-failure rollback, candidate read-only READY/ABORT | `native-history-sync-debug-owner-final-native.log`, `native-history-sync-release-safe-owner-final-native.log` |
| Native listener readiness race regression, Debug and ReleaseSafe each 200/200 executions of 72/72 tests | `reuseport-race-fixed-debug-native-200.log`, `reuseport-race-fixed-rs-native-200.log`; pre-fix `reuseport-race-before-rs-native-200.log` |
| Actual native pledge/unveil and inherited fork/exec authority | `openbsd-sandbox-probe-native.log` |
| Native test-runner sandbox isolation plus descriptor and EINTR regression, 75/75 in each mode | `pledge-isolation-openbsd-native-debug.log`, `pledge-isolation-openbsd-native-release-safe.log` |
| Native PortableServer client ABI, enabled NODELAY and 64-cycle nick/QUIT/channel cleanup, 74/74 in each mode | `portable-native-fixtures-debug-final-native.log`, `portable-native-fixtures-release-safe-final-native.log` |
| Current clock/token regression | `sessiontoken-clock-openbsd-debug-native.log`, `sessiontoken-clock-openbsd-release-safe-native.log`, `auth-clock-token-root-debug.log` |
| Final whole-daemon Linux, FreeBSD and Windows compile checks, 3/3 each | `full-port-consolidated-linux-check.log`, `full-port-consolidated-x86_64-freebsd-check.log`, `full-port-consolidated-x86_64-windows-check.log` |
| Fixture cleanup, zero daemon PIDs and exact alias/PF restoration | the final session logs above, `native-consolidated-final-rs-cleanup.log` and `native-consolidated-final-global-cleanup.log` |

Final consolidated native daemon SHA-256:

- Debug: `8f45073cda5e75a8589e09d7c3590df0b2e667bdb4e91e4e678cc6b3d182269a`.
- ReleaseSafe: `9e083f445abc3b5d97036e58a121270a914db5ecbfbdced3ee1e79a1eb38d975`.

Build metadata was generated at HEAD `15e09029` with the accepted working-tree
changes. The tested server source is
`063206384e104ae256b0816c1d807c9918bff348539f4941770dc261a9d97849`;
`consolidated-source-hashes.log` also records the memo/history source and the
matching native checkout archive. These pins identify the tested binaries
independently of the later local source commit.

OpenBSD returns the enabled TCP_NODELAY bit rather than Linux's numeric `1`.
The native fixture requires a successful four-byte readback and a nonzero
value; Linux retains its exact `1` assertion. This follows the documented
[boolean TCP option](https://man.openbsd.org/tcp.4) and independently checked
[kernel GETOPT implementation](https://github.com/openbsd/src/blob/master/sys/netinet/tcp_usrreq.c).

The session probe checks immutable artifact hashes, distinct pinned identities,
original socket custody, unchanged tokens, and matching message IDs/timestamps.
Delivery counts use cumulative checks and a finite drain window; deterministic
relay/replay tests supply additional evidence. These counts are not a claim
about every possible future delivery schedule.

Run the native full unit suite by building without `-Dtest-filter`, then copying
and executing all three installed runners on OpenBSD:

```sh
zig build test-artifacts -Dtarget=x86_64-openbsd -Doptimize=ReleaseSafe --summary all
# On the guest, from a writable matching source checkout:
# Some source-witness fixtures read repository files; GAP-P11 embeds its source.
ulimit -s 65536
# Raise only the soft descriptor limit to the existing hard allowance if needed.
./onyx-server-module-tests
./onyx-server-daemon-tests
./onyx-server-cli-tests
```

The build step installs binaries without executing them. Compile success alone
is not native unit acceptance. Native runner execution is tracked in the
[port record](../../../dev/openbsd-full-port.md).

Fresh independent read-only reviews covered native arena/image/descriptor
custody, candidate failure boundaries, completion ownership, replay repair,
clock/token authority, test isolation, build steps, and Python alias/PF cleanup
plus bounded redirect retries. No blocking source finding remained.

Existing shared far-nickname routing, same-IP dial matching, and TOTP storage
failure concerns are described in the port record; these gates do not close the
whole historical roadmap. Private node keys, account credentials, configs and
WAL images are excluded from this evidence directory.

Fresh independent acceptance: [final-acceptance-review.md](final-acceptance-review.md).

The rejected candidate allocator diagnostics are disclosed in the independent
[exit allocation review](final-exit-allocation-review.md): a pre-existing
694-byte ISUPPORT leak at failed-process exit, with native descriptor cleanup
intact. Evidence-local `.gitattributes` preserves exact raw log whitespace.
