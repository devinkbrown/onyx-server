<!-- SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com> -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Full OpenBSD runtime port

Requested 2026-09-30. The target is the shipping Linux daemon's product
behavior on OpenBSD, including secured mesh sessions and connection-preserving
Helix. The native plaintext evidence in the continuation audit is an accepted
starting point; it is not full-port acceptance.

## Architecture and ownership

Use the existing complete server lifecycle on OpenBSD. Keep Linux's Ringlane
implementation and implement the same completion contract over kqueue. Do not
duplicate services, session authority, routing, or upgrade serialization in
the separate minimal `PortableServer`.

| Work | Owner | Files |
|---|---|---|
| Shared full server lifecycle and native runtime seams | integrator | `src/daemon/server.zig` only |
| Completion facade, native connect/cancel, cross-thread wake | IO leaf | `io_backend.zig`, new `reactor_backend.zig`, `reactor_wake.zig` |
| Native descriptors/listeners, boot, confinement, Helix and worker leaves | parent | new `os_runtime.zig`, `reuseport.zig`, `kernel_other.zig`, `main.zig`, `config_boot.zig`; further leaf ownership recorded before editing |
| Independent source and native acceptance review | reviewer | read-only |

Native errors and socket addresses use the target ABI. Linux numeric errno,
socket constants, `sockaddr`, control messages, and time structures must not
cross into a BSD syscall. Original canceled operations must produce terminal
completions before buffers and client slots can be released or sealed.

OpenBSD IPv6 sockets cannot serve IPv4-mapped traffic. Wildcard parity requires
separate IPv4/IPv6 listeners and explicit ownership through adoption. Duplicate
`SO_REUSEPORT` binding alone does not establish Linux-style load distribution.
See [OpenBSD inet6](https://man.openbsd.org/inet6.4).

## Required acceptance

| Area | Required evidence | Current status |
|---|---|---|
| Backend and descriptor lifecycle | native Debug/ReleaseSafe, allocation failures, cancel races, fd reuse, connect success/refusal | actual OpenBSD Debug/ReleaseSafe full facade 83/83; signal-interruption extension 77/77 in both modes |
| Full IRCX/services/history | native registration, commands, SASL/account state, durable restart, rehash/plugins | actual Debug/ReleaseSafe REGISTER into three separate WALs; PLAIN before NICK, opaque SESSION-TOKEN and password authentication after cold restart pass |
| TLS/WebSocket/STS/PROXY | native TLS 1.2/1.3 application exchange, secure WS, policy/refusal cases | native TLS 1.2 218/218 and media/TLS 104/104 in both modes; real full-daemon TLS 1.2/1.3 and WSS registration over IPv4/IPv6 |
| Mesh and reusable sessions | native secured three-node topology, signed relay, partition/rejoin, exact-once, migration | actual Debug/ReleaseSafe distinct-host secured A-B-C line: PF partition/rejoin, four original reusable attachments, all three sequential upgrades, fifth far resume; 51 accepted events / 243 bounded exact recipient deliveries with equal msgid/time |
| Sharding | real cross-reactor delivery/wake, fd ownership, IPv4/IPv6 acceptance | actual native shared-server Debug/ReleaseSafe 76/76; wildcard listener ownership, cross-reactor traffic, and IPv4/IPv6 TLS/WSS pass |
| Helix | sequential upgrades retain all physical attachments, TLS/S2S state and tokens; failed candidate leaves predecessor serving | native history synchronization passes 76/76 in both modes; two real upgrades retain 40 original mixed plain/TLS 1.2/TLS 1.3/WSS IPv4/IPv6 sockets; a missing-identity candidate is rejected with all 40 originals alive, followed by two successful upgrades; middle-node MESSAGE_V2 replay/retry checkpoint repaired and actual three-node upgrades pass in both modes |
| Network workers | metrics, HTTP hooks/fetch, ACME/OCSP, webpush, media/native media/WebTransport | HTTP/DNS 88/88, media/TLS 104/104, history HTTPS 75/75, ACME/OCSP worker fixtures 116/116 in both native modes; real SMTP STARTTLS and encrypted WebPush 201/410 protocol probe passes 2/2 in both modes after stack correction |
| Confinement | configured paths accessible, required promises explicit, upgrade candidate authority preserved | configured-path unveil and inherited pledge implemented; actual fork/exec sandbox probe passes; full-daemon cold boot and sequential upgrades operate under confinement |
| Linux regression | final full suite, critical Debug/ReleaseSafe and fresh review | consolidated full Debug and ReleaseSafe each pass 8761/8785, 24 skipped, zero failures; fresh independent source and probe reviews approved |

Final unfiltered native Debug and ReleaseSafe each execute 8732 module tests:
8584 passed, 148 skipped and zero failed. The daemon test root has zero tests;
the CLI passes 51 tests with two skips in both modes. These are actual native
executions of all three installed runners, from a matching writable checkout.
The nine discovered fuzz entry points are not a claim that fuzz campaigns ran.

The expanded suite exposed four fixture assumptions, a peer-side EOF race,
and a real memo returned-stack-slice defect. All six are repaired. The shutdown
fixture still requires a sub-second join, zero reader calls, and no response
bytes; EOF/reset has a separate fixed one-second bound. Direct memo decisions
borrow caller input, while forwarded targets remain store-owned. Fresh review,
allocation-free ownership regressions and native focused repetitions cover the
repairs. The fixture record includes the reproduced WHISPER race and its
200-run ReleaseSafe regression.

Final pinned ReleaseSafe confined plugin startup and authenticated REHASH
pass: the replacement command loads, the old command returns 421, and the
original TLS connection still answers PING. STS/PROXY policy coverage remains
unit-level; native transport probes establish real registration and exchange.

OpenBSD does not expose Linux `memfd` sealing or `execveat`. Helix must retain
immutable snapshot and executed-image authority with a native process strategy.
A writable temporary arena or a pathname probe followed by a second path exec
does not satisfy those invariants. The implemented strategy validates an immutable executed image first, keeps
predecessor-held state, and uses a transactional commit handshake. Independent
review approved the native descriptor, arena custody, image authority and
pre-commit failure boundaries; actual rejected and successful candidates are
covered by the native gates above.

No production deployment or publication is part of this port authorization.

## Native acceptance findings

The first 40-client upgrade rejected its successor after a descriptor-count
arithmetic overflow. `native_manifest.receive` now uses an explicit `usize`
count; a native 65-descriptor regression covers three indexed batches. The
serving predecessor remained available when the failed candidate exited.

Subsequent live upgrades retained every original plain/TLS 1.3 connection,
including a second upgrade with 20 clients owned by each reactor. Mixed TLS
1.2/WSS adoption reached native pre-commit checks, where the candidate correctly
refused to rewrite a divergent durable history image. The required fix belongs
at the predecessor's authoritative seal boundary; successor storage stays
read-only until COMMIT. The predecessor now synchronizes the canonical durable
image before sealing. Native Debug and ReleaseSafe tests verify allocation
failure leaves the checkpoint intact and physical WAL bytes remain unchanged
through candidate READY and ABORT. The corrected mixed-transport gate passes
two upgrades with every original connection retained.

Actual WebPush HTTPS delivery exposed a Debug stack overflow in the worker's
512 KiB thread. Nested TLS client and hybrid key-exchange frames exceeded that
budget. A 2 MiB worker stack passes the real SMTP/WebPush protocol probe, including
independent payload decryption, VAPID verification, and dead subscription pruning.

The secured A-B-C reusable-session probe passes in both native modes, including
actual PF partition/rejoin, all three node upgrades, retained events, stable
original attachments and tokens, and cold account authentication. Its bounded
cumulative oracle observes 51 accepted events and 243 recipient deliveries.
The middle-node strict validator exposed an originating state error: duplicate
ingress could revive a retry already confirmed by that peer, leaving a retry
without its retained event after the final ACK. Retry allocation now excludes
confirmed peers under the relay lock; checkpoint validation remains strict.

Opaque SESSION-TOKEN issuance previously used monotonic uptime while verification
used Unix time, causing immediate expiry. Issuance and verification now use a
checked wall clock and reject absent/nonpositive time. Verification also binds
the token to the account's current hash, rejecting orphan records after rotation.
Native unit gates and actual cold WAL authentication cover these changes.

The unfiltered native suite exposed an additional production omission: OCG1
operator grants and webhook snapshots called a Linux-only file writer. The
shared writer now uses target-native open, partial-write/EINTR handling and
close on OpenBSD. Configured writable parent directories already belong to the
unveil plan. Native persistence/reload tests exercise the corrected path;
its existing best-effort behavior is unchanged.

Shared-server fixture coverage was also opened on OpenBSD: 19 threaded,
62 positive-guarded and 346 negative-guarded tests now admit the native target.
Linux kernel and legacy arena fixtures keep their explicit platform guards.
Native fixture helpers use checked socketpair, connect, accept and file paths;
bounded readiness retries still fail on timeout or non-transient errors.
The boot-dial cursor fixture checks native queued changes and retains every
fairness assertion.

Pure-memory clients have no physical descriptor. Their declared test-only
SendQ capture flag prevents native submission of the synthetic descriptor;
its storage and arm branch compile out of the daemon. An untagged invalid
descriptor still fails native validation. The two RESYNC resume assertions,
reciprocal mesh dialing and cross-shard LUSERS all pass actual native Debug
execution without skips. This fixture capture mode does not establish socket
I/O acceptance; the separate real-transport and mesh gates do.

The fixture models distinct hosts with three explicitly owned loopback aliases.
It restores the original PF rules and aliases and confirms zero fixture PIDs.
A valid SESSION REDIRECT is retried with the same credential within the existing
40-second deadline; only a real attachment response can pass the probe.

Two existing shared mesh limitations remain outside this operating-system port:
a far-only unbound nickname can return 401 in a line topology, and the inbound
dial fallback compares peer IP without distinguishing colocated same-IP nodes.
The latter can suppress a redial after a partition in a same-IP fixture.
Both paths match the pre-port source; neither is counted as solved by these
native gates. Shared-authoritative-session channel and direct delivery are
covered across all three distinct hosts. Storage-fault atomicity for TOTP token
revocation also remains a separate shared-services concern. The original port acceptance
exposed a pre-existing 694-byte ISUPPORT allocation leak on the rejected
candidate's missing-key error return. The subsequent
[ISUPPORT cleanup follow-up](../audit/evidence/isupport-exit-2026-09-30/README.md)
clears the global override and frees the tokens after server teardown. The
same isolated missing-key refusal reproduces 16 leak records on the pre-fix
commit and zero records in patched Linux Debug and ReleaseSafe. Native OpenBSD
Debug and ReleaseSafe reproduce the same before/after result. This follow-up has an OpenBSD
compile check; the original mesh/transport runtime evidence remains pinned to
the original port artifacts. Explicit process-exit calls still bypass
deferred cleanup.

The native reactor now treats interrupted `kevent` waits as an empty poll,
preserving registered operations and buffer custody. A syscall-return-only
trace observed EINTR during real upgrades; deterministic native tests verify
the original armed receive completes exactly once afterward.

`tools/openbsd_runtime_smoke.py` uses caller-owned IPv4/IPv6 SSH forwards and checks
original plain/TLS 1.2/TLS 1.3/WSS sockets through sequential upgrades. Message
counts describe a bounded observation window; they are combined with the
server's deterministic relay/replay gates, rather than treated as a proof that
no duplicate could arrive at any future time.
