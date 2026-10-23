# Nickname recovery, connection logging, and Helix probe release

Release source: `2a7bbcb71348e2b61152bb8bfafb5ffbf425b8a6`.
Version: `0.8.1+2a7bbcb71348`.
Reproducible artifact SHA-256:
`98cd6ecf03b47fb358f08b6545372b213fa5c88d21b7aa27e37ff75fe10b91b5`.

## Corrected behavior

Both production nodes reproduced the reported registration failure: CAP
negotiation completed, an unauthenticated protected nickname received numeric
432, and the server closed TLS before the client could select another nickname.
The fix rolls registration back before publishing a welcome, World identity, or
session. It preserves USER/CAP/authentication state and permits fallback NICK or
owner authentication. The same guard covers challenge release. A full denial
reply queue is contained to the affected connection. Registered-name ownership
checks remain enforced.

Connection diagnostics now distinguish accept, adoption, registration, explicit
QUIT, EOF, receive/send failures, TLS failures, parser/buffer failures, nickname
denial, and final close. Records include UTC milliseconds, physical connection
identity, peer address, escaped nickname, transport, and numeric/error categories.
They omit raw commands, authentication payloads, passwords, session tokens,
message contents, and arbitrary QUIT text. A process-wide monotonic budget allows
128 events per fixed one-second window and reports suppressed records on the next
admitted event.

Optional Linux `[logging].stderr_file` opens a daemon-owned `0600` regular file
with one hard link, without truncation or following a final symlink. Config
preflight may create the file and must run as the daemon user. Cold startup and
Helix successors open the sink; a runtime failure preserves inherited stderr
and does not abort live-state adoption.

An isolated rehearsal also reproduced a Helix probe failure: the predecessor's
`std.process.run` opened `/dev/null` read/write under a Landlock policy permitting
only reads. The replacement probe supplies EOF through a closed stdin pipe,
limits each captured stream to 4 KiB, and uses one two-second deadline for output
and child exit. It forcibly terminates and reaps a stuck child without weakening
the sandbox. No checkpoint layout or capability-token change was required.

## Release evidence

Toolchain: `/tmp/zig-017/zig-x86_64-linux-0.17.0/zig`, version `0.17.0`;
`-Doptimize=safe` selects ReleaseSafe in this toolchain.

- Nickname regression failed before the fix with `ConnectionReset`; final focused
  nickname tests passed 78/78 in Debug and ReleaseSafe.
- Persistent-sink tests passed 78/78 in Debug and ReleaseSafe, covering append,
  private ownership/mode, rejected unsafe destinations, descriptor replacement,
  and parser allocation failures. Combined nickname/diagnostic Debug passed 80/80.
- Probe negative control failed before the fix (73 passed, one failed); final
  focused probe tests passed 76/76 in Debug and ReleaseSafe, including oversized,
  slow-output, and closed-output/hung-child cases.
- Final affected Debug gates passed 3,253 tests, with 106 platform skips; build
  check passed. The final full Debug suite is not claimed complete.
- Final full ReleaseSafe command was `zig build test-verbose check wasm fuzz
  bogo-shim-test -Doptimize=safe --summary all`. Module tests passed 10,116 with
  322 skips; main and CLI tests passed another 65: **10,181 passed**, zero failed,
  leaked, or log errors. Fuzz and BoGo added 99 passes; all 24 build steps passed
  in 1,833.01 seconds.
- `packaging/release.sh` built the clean release; `packaging/verify-release.sh`
  rebuilt from a clean cache and confirmed byte identity plus manifest integrity.
  No signing key was configured, so no signature is claimed.
- Isolated same-image Helix rehearsals preserved 12 physical connections across
  two shards, including plain IRC, TLS, and mid-frame WSS, unchanged tokens, and the
  same PID. Valid and unavailable logging destinations both passed. Local kTLS
  was unavailable; a separate ircx.us rehearsal verified active kernel TX before
  and after adoption, including four adopted kTLS connections among 12 total.
  These fixtures did not configure WebTransport.

Independent review approved the release evidence. The recorded source hashes
did not change during final gates. All touched files pass formatting; 205
full-tree formatter findings are unchanged baseline debt, not a green full-tree
format check. Gate and package evidence is recorded in
`/tmp/onyx-final-2a7-gate-ledger.json` and `/tmp/onyx-final-2a7-*.log`.
The subsequent smoke-fixture/reference update `91ecc3ff` does not change the
deployed binary.

## Accepted production state

The user authorized both-node deployment and GitHub publication. Rollout used
one-node-at-a-time cold restarts because the old image could not run its probe
under the inherited sandbox. Acceptance completed at **2026-10-23 18:25:58 UTC**.
Installed and executing hashes on both nodes match the release artifact.

| Evidence | eshmaki.me | ircx.us |
|---|---|---|
| Supervisor | OpenRC, started | systemd, active/running, `NRestarts=0` |
| PID | `18189` | `2181421` |
| Log sink | `/home/kain/onyx-server-run/onyx-server.log`, mode `0600` | persistent journal |
| Mesh | `links_active=1`, `peers_up=1`, `tcp_active=1`, `partitioned=0` | same |

The local log contains connection and secured-mesh events; its dedicated
`onyx-logrotate` service is active. Remote diagnostics include active kTLS.
Local config gained the logging destination; remote config remained unchanged.
Each runtime contains `rollback-2a7bbcb7-20261023T181147Z` with the previous
binary/config. Previous artifact SHA-256 is
`258dadd825a05b5039fffa35306b781f463d7f1c69dcbf632a249fd5bb08737f`.

Both nodes passed protected-name rejection followed by same-TLS-socket fallback,
welcome/PONG, and account registration. Persisted-account login, fresh-token
reconnect, and cross-node TLS chat passed. Cold restart drops physical
attachments; these checks do not prove old exact-token recovery across it.

## Remaining limits

**Production Helix did not execute.** Both live configs enable WebTransport on
UDP 4433. The pre-existing Linux `upgradeContinuityBlockerLocked` guard in
`server.zig` refuses its process-owned listener state before exec. Local USR2
returned the generic `SessionReplicaConverging` error while preserving PID 18189
and serving connections; this was not evidence of a mesh partition. The remote
node was not signaled. Disabling WebTransport changes listener topology and also
requires a cold restart. This release does not provide a zero-drop upgrade for
the current production topology.

After the refused signal, the held-client test verified original TLS sockets,
unchanged exact tokens, membership, 14 reciprocal delivery rounds, and
authenticated reconnect/resume on both nodes. Its generic “PASS Helix attachment
acceptance complete” label is qualified by the deployment receipt: it proves
continuity after refusal, not successful exec/adoption.

An initial scratch harness stopped before signaling because its NAMES parser
misread an owner prefix. It lost the randomly generated credentials for two test
accounts: `hxacc63d4b4fa41` on eshmaki and `hxaccae3f758535` on ircx. Those orphan
accounts remain; no account-store mutation or authentication bypass was used to
remove them. The repaired run removed both of its new temporary accounts.

Ariadne's earlier disconnect cause remains unresolved. Persisted events matched
the reported timeline, but their generic `Client quit` reason did not identify
the initiator. A pre-deployment 30-minute header-only observation saw 345 matching
packets and no connection close. Ariadne registered again after rollout, with no
later closure observed by approximately 18:24 UTC. This observation is not a
causality claim or a guarantee against future drops; new diagnostics provide
more specific evidence for recurrence.

The final production receipt is
`.release/log-check/deploy-2a7bbcb7-receipt.json`. Current paths and commands are
in [the production paths document](../ops/onyx-server-paths.md).
