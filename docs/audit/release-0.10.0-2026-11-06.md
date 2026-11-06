# Release verification, 0.10.0, 2026-11-06

Both production nodes run `0.10.0+ef2230805c16`, built from clean commit
`ef223080`. The static x86_64 Linux musl artifact was rebuilt from source by
`packaging/verify-release.sh` and is byte-identical, SHA-256
`b9cee11f55b563ebb226fa0a470584d2772f5a3cfe7b922abd94e17d0cda082f`.
The fleet record lives in [production paths](../ops/onyx-server-paths.md);
release notes are in [NEWS](../../NEWS.md#0100--roadmap-wave-fleet-release-2026-11-06).

## Scope

The release merges the roadmap wave (M02 adaptive anti-entropy, M03 digest
sync, M04 route cost, M10 upgrade plan, M12 S2S admission, T07 attachment-revoke
fence, T09 credential churn, Q01 existence privacy, Q04 permission explain,
Q05 moderation undo, Q06 ACCESS expiry reminders, Q07 config change preview,
W09 resource limits) and the supporting operator and mesh modules. The commit
touches 68 files.

## Test evidence

Compiler: Zig 0.17.0.

| Gate | Result |
|---|---|
| Full Debug `zig build test` | 12,086 discovered, 11,773 passed, 313 skipped, 0 failed, 0 leaked, 0 log errors (about 14 min) |
| ReleaseSafe `test-session`, `test-helix`, `test-mesh` | 3,181 passed, 98 skipped, 0 failed |
| Leaf lanes (13, including entrypoint, cloak, service identity, spool, exec helpers) | all passed |
| `zig fmt --check`, diff check | clean |

Two independent review passes, using the mechanical, integration and security
lenses, were run against the merged tree. The first found five defects, each
fixed with a regression test:

1. The M12 S2S ticket key was shared, so one source could starve others.
2. M12 admission ran before the per-IP throttle.
3. The T07 attachment-revoke fence was not carried across Helix.
4. `src/root.zig` exported the exec-helper test roots.
5. `src/root.zig` exported a temporary test root.

The second pass, over the newly merged delta, found nothing.

The gate also surfaced two pre-existing flakes, both fixed in this release. A
three-node MARKREAD exact-once test failed when the MESSAGE_V2 ACK raced ingress
commit. A four-client Helix test failed on adopted-shard placement, now
round-robin.

## Artifacts

| Target | SHA-256 | Reproduced |
|---|---|---|
| `onyx-server-0.10.0-x86_64-linux-musl` | `b9cee11f55b563ebb226fa0a470584d2772f5a3cfe7b922abd94e17d0cda082f` | yes, byte-identical |
| `onyx-server-0.10.0-aarch64-linux-musl` | `0fb2c89409e6821c4144c35380227c015ee3f749b4b2e0605296ee91157e3f7b` | yes, byte-identical |

Both are built by `packaging/release.sh` with a CycloneDX SBOM and SLSA-shaped
provenance. No cosign signer was configured, so `SHA256SUMS` is unsigned. The
aarch64 artifact was not deployed.

## Deployment

1. Captured rollback state. Both nodes ran `0.9.0+5bdd9dc55d99`
   (`2dcc8990…`) with `links_active=1`. The old binary is kept as
   `onyx-server.0.9.0-5bdd9dc5` beside each live binary.
2. Ran `--check-config` with the new binary against each live config: both
   returned `config OK`.
3. Cold-restarted eshmaki.me (OpenRC), confirmed `/proc/<pid>/exe` matched the
   artifact hash, and saw `mesh S2S established (secured) peer=ircx.us`.
4. Cold-restarted ircx.us (systemd), with the same checks, and saw
   `mesh S2S established (secured) peer=eshmaki.me`.
5. `tools/mesh_health_smoke.py` on both nodes reported `links_active=1`,
   `peers_up=1`, `partitioned=0`, `tcp_active=1`.
6. `tools/mesh_chat_smoke.py` with CA-verified TLS and guest clients on
   `#root` delivered PRIVMSG eshmaki.me → ircx.us and ircx.us → eshmaki.me.

Helix stays blocked on both nodes by WebTransport, so the rollout used cold
restarts.

## Limits

- Token resume after the cold restart was not exercised by a dedicated
  fixture. A live client reconnected and registered after each restart. The
  0.9.0 acceptance exercised token resume; see
  [the 2026-11-03 record](release-and-test-speed-2026-11-03.md).
- The leaf lanes finished after deployment. The full Debug gate and ReleaseSafe
  critical lanes had passed before it.
- Known design limits shipped in this release: AKILL/GLINE cannot be undone;
  the moderation and enrollment ledgers are node-local; M03 accepts a
  hidden-loss window of up to 10 minutes before full repair; M04 does not gossip
  link cost beyond direct neighbours; the S2S handshake timeout has no TOML key.
- Metric rename: `onyx_session_credential_table_evictions_total` is now
  `onyx_session_credential_table_overflow_total`.
