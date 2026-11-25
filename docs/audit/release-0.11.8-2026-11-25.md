# Release verification, 0.11.8, 2026-11-25

Both production nodes run `0.11.8+75b20aaa9986`, built from clean commit
`75b20aaa9986e9fb7479451346c7bc72e23d2ebc`. The accepted static x86_64 Linux musl
artifact has SHA-256
`a967ea8d9d882f1b81db6520bd64d46106897a9ae2ad144797a9ba98518491ad`.
Deployment was accepted on **2026-11-25 at 00:42:56 UTC**. The current fleet
inventory is in [production paths](../ops/onyx-server-paths.md).

## Scope and limits

The [receive completion path](../../src/daemon/server.zig) previously sent every
negative kernel TLS RX completion through a second control read. For a genuine
TCP timeout, that second read could return `Eof` and overwrite the true cause as
TLS record failure. Only `EIO` and `EKEYEXPIRED` now enter the control reader;
timeouts and resets retain their transport reason. Kernel authentication,
record-size and version faults remain fatal TLS errors. Regression tests check
armed SEND ownership, terminal alerts, exact QUIT finalization and control demux.

This corrects error handling and classification. It does **not** establish or
prevent the cause of the historical network timeouts.

The release also includes client-contract revision 4 and its validator/tests,
SESSION request/response and WebSocket application-message corrections, and the
[proposed Elm client roadmap](../design/onyx-elm-client-roadmap.md). Those documents
do not promote a planned client feature to deployed runtime acceptance.

## Source and artifact evidence

| Input | Accepted value |
|---|---|
| Source | `75b20aaa9986e9fb7479451346c7bc72e23d2ebc` |
| Compiler | Zig `0.17.0` |
| Compiler SHA-256 | `7c61539af19fa4082c94848f1c2b57b89e76dc6cfd5bd4c57764c3caf8f82272` |
| Target / CPU / mode | `x86_64-linux-musl` / `baseline` / ReleaseFast |
| Artifact | `onyx-server-0.11.8-x86_64-linux-musl` |
| Artifact size | 22,336,632 bytes |
| Artifact SHA-256 | `a967ea8d9d882f1b81db6520bd64d46106897a9ae2ad144797a9ba98518491ad` |

Two independent invocations of [packaging/release.sh](../../packaging/release.sh)
used the same clean source, exact compiler and flags, each with a fresh cache.
The binary, build metadata, CycloneDX SBOM, provenance and `SHA256SUMS` were
byte-identical, and both manifests verified every entry. This was an independent
second release build and full comparison, not a third rebuild through
`verify-release.sh`.

## Test and review evidence

| Gate | Result |
|---|---|
| `zig build all-checks --summary all` | 21/21 build steps; full aggregate 12,479 discovered/executed, 12,166 passed, 313 skipped, zero failures/leaks/log errors; 1,196.194 s |
| `zig build test -Doptimize=safe --summary all` | 7/7 build steps; same 12,479 discovered/executed, 12,166 passed, 313 skipped, zero failures/leaks/log errors; 1,945.412 s |
| Debug deterministic fuzz / BoGo self-tests | 100/100 and 21/21 passed |
| Focused receive diagnostics, Debug and ReleaseSafe | 94/94 selected cases passed in each mode |
| Client contract | Semantic validation and all 24 Python regression tests passed |
| Formatting and documentation | `zig fmt --check src/`, `git diff --check` and documentation checks passed |

All three changed receive-diagnostic cases, the real configuration-admitted
kernel TX/RX attach and rekey case, and the pre-attach single-shot receive
regression passed in both modes; none was skipped. The full inventories cover
the selected server, services and TLS gate cases. A fresh independent read-only
source and final-test review approved the change.

The exact shipped artifact also passed the isolated runtime smoke, real Chromium
TLS 1.3/WebSocket registration and PING/PONG with X25519MLKEM768, and an isolated
USR2 upgrade from the deployed 0.11.7 predecessor with carried client/session and
channel state.

## Deployment and live acceptance

The operator captured each supervisor, process identity, executable/config hashes
and rollback files, checked the candidate against both live configs, then used
Helix through the actual supervisors: **ircx.us first, eshmaki.me second**.
No cold restart occurred and neither config changed.

| Evidence | eshmaki.me | ircx.us |
|---|---|---|
| Manager | OpenRC | systemd |
| PID before/after | `26437`, kept | `2980332`, kept |
| Presence issuer epoch before/after | `15`, kept | `12`, kept |
| Running and on-disk artifact hash | accepted artifact above | same |
| `links_active` / `peers_up` / `partitioned` | `1 / 1 / 0` | `1 / 1 / 0` |

Local Helix carried the ACME scheduler checkpoint: next check in 15,474 seconds
at adopt, 24 completed checks, last result `not_due`.

Four CA-verified physical TLS clients, one TLS 1.2 and one TLS 1.3 on each node,
stayed on their original sockets across both upgrades. Each retained its own
exact local credential. Before staging, after staging, after each node's reload
and after both reloads, four authored events produced exactly 16 deliveries per
phase; every recipient observed the same `msgid` and `time` for each event.

A separate post-deployment probe closed one attachment on each node and resumed
its own preissued exact credential. Both restored channel participation without
JOIN and participated in exact-event delivery across all four clients. It honored
`WARN SESSION TEMPORARILY_UNAVAILABLE` with bounded retries of the unchanged
credential: four total attempts locally and five remotely. This warning preserves
the credential; it is not a reason to replace it or downgrade its kind.

Fresh CA/hostname-verified TLS 1.2 and TLS 1.3 clients on both nodes registered
immediately and round-tripped PING/PONG. The public status JSON reported active
MESSAGE_V2, activation epoch 1, two roster members and digest
`879ef8edfa22a2125e32f757c65e81f76264144dd328b934eb4454a8bf5dbb4d`.
All fixture-owned accounts were removed and private fixture credentials deleted.

The initial probe was corrected to respect exact-physical credential semantics
(`ATTACHMENT_IN_USE` for a live exact selector), optional MTOKEN emission and
retryable resume warnings. No legacy credential kind stripping or additional
reload was used to make those checks pass.

## Rollback custody

Both runtime directories retain `onyx-server.0.11.7-517c17bf`, SHA-256
`517c17bf0ea67066748a11d3921ad0610d144457a440499aee4977b9c00a4a77`, and config backup
`onyx-server.local.toml.bak-pre-0.11.8-20261125`. A rollback still requires current
capability/config checks and the [runbook](../RUNBOOK.md) custody rules; retaining
an old binary does not authorize replaying an older WAL or skipping live-state
guards. Exact attachment recovery across an arbitrary cold boundary was not
claimed by this Helix rollout.
