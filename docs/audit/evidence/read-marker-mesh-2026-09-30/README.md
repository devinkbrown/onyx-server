# Account read-marker mesh acceptance

Baseline: `114e1cd4`. Work began 2026-09-30; final acceptance runs on 2026-10-01.
No production deployment or GitHub push. Final source pins: `source-sha256.txt`.
Test binaries were built from the dirty tree based on `114e1cd4`; their build
metadata predates the eventual local commit. Source pins identify the exact eight
changed compilation inputs. The local commit records that verified source.

## Behavior and boundary

Authenticated SET synchronously admits one account/target durable row containing
the timestamp and exact original signed fact, plus an independent marker clock,
before publishing runtime state or notifying physical account attachments.
Timestamp-max merge prevents older read positions from winning because of later
HLC or arrival order; equal-position facts have a deterministic byte-order winner.
Reserved private ENTITY_PROP facts never enter generic PROP state or public
notifications. Only established secured links with explicit marker support carry
facts; original signatures are verified on admission and forwarded unchanged.
Retained winners repair capability appearance, reconnect, RESYNC and partitions.

The socket tests use distinct stores on A-B-C, all attached shared-account clients,
real SET/GET and unsolicited replies, opposite-edge authorship, partition/heal,
exact origin bytes and opposite-edge resume. Sequential Helix tests keep four
clients connected through both upgrades and then resume a fifth attachment.

Guests use memory-only physical connection identity and have no process-restart
continuity claim. Legacy untyped durable rows stay local until an explicit
account-authenticated SET promotes a signed fact. Privacy assumes consistent
canonical Services account provisioning across authorized mesh nodes; this slice
does not solve independent same-name accounts or global directory ownership.

## Upgrade compatibility and review

Both Linux and native current writers require `read-marker-mesh-v1` before live
service-descriptor handoff. Frozen predecessor contracts preserve old-to-new
upgrades. New-to-old hot downgrade is refused because older generic property
readers could expose carried private ciphertext. No ciphertext deletion or AEAD
counter rollback is used. The real v4-only ELF fixture proves descriptor, queue,
frontier and clock custody; ordinary refusal-audit queueing preserves original
ciphertext and produces exactly one verified audit.

Fresh leaf and integration reviewers found and then verified fixes for unsafe
hot downgrade and outer-OOM plaintext residue. See `review-leaves.md` and
`review-integration.md`; reviewers did not author these source changes.

## Fault and fixture evidence

Local and remote allocation admission each induce 16 failures before successful
retry; restore induces seven failures. Durable tests exercise abandoned prepare,
short/failed writes, sync ambiguity, cold resolution, and compacted bounded rows.
The outer-OOM RED left 319 plaintext bytes; the unchanged regression now requires
both queues empty, retained exact frontier, successful retry and deduplicated
admission. `outbound-pressure-red.log` retains the original failure.

Initial native Debug failed on stack probing in an existing threaded fixture.
Large test servers now use heap allocation, preserving all assertions and native
8192 KiB stack limit. Three broad rewind failures were authenticated custom-SASL
fixtures lacking durable Services; they now use real stores and retain every
command and history-policy assertion. See RED logs and Debug/ReleaseSafe bouncer
74/74 receipts. `integrator-production-parity.txt` proves late changes were test
fixtures only.

## Native OpenBSD

OpenBSD 7.9 amd64, normal 8192 KiB stack. Final Debug and ReleaseSafe artifacts
are executed inside the owned QEMU guest. Module runner: 91 passed, three skipped,
zero failed / 94. Skips are the two existing Linux-only topology/Helix cases and
the Linux/x86_64 executable refusal fixture. CLI runner: 2/2; daemon runner has
zero selected tests. Do not count the empty runner as daemon coverage.

Artifact hashes, build/check logs, full raw runner logs and execution exit codes
are adjacent. This new marker slice does not claim a new native multi-host live
campaign. The earlier full-port acceptance remains documented in
`docs/dev/openbsd-full-port.md`.

Owned guest fixture was removed and QEMU shut down; port2225 is closed. Existing
port2223 OpenBSD and port2222 FreeBSD VMs remain reachable. See cleanup receipt.

## Final Linux gates

All final gates passed on the pinned source. Named gates overlap; their counts
must not be added to the full-suite count.

| Gate | Debug | ReleaseSafe |
|---|---|---|
| Full suite | 8811 passed / 8835; 24 skipped | 8811 passed / 8835; 24 skipped |
| MARKREAD focused | 94/94 | 94/94 |
| Server | 468 passed / 472; 4 skipped | 468 passed / 472; 4 skipped |
| Services | 566/566 | 566/566 |
| Helix | 775 passed / 780; 5 skipped | 775 passed / 780; 5 skipped |
| Mesh | 506 passed / 508; 2 skipped | 506 passed / 508; 2 skipped |

Every row has zero failures. Full results have 8758 module passes plus 53 CLI
passes; the empty selected daemon runner adds no coverage. Final named ReleaseSafe
commands ran together in the project build: 13/13 steps, 2315/2326 passes, 11 skips,
exit 0, 470.21 seconds. Individual named counts and compile/run durations are in
`selected-rs-final.log`; Debug command timings are in `final-selected-results.txt`.
Linux and native build checks, full source formatting and diff checks pass.
`full-results.txt`, `full-debug.log` and `full-rs.log` retain full counts and exits.

The prior failed bouncer full runs are retained as RED evidence. The final store
fixture correction resolves all three failures without changing production code.
Interrupted scheduling/compiler logs are not used as acceptance evidence.

Raw work logs remain in `.zig-cache/codex-resume/read-marker-mesh/`. Evidence
copies normalize only trailing whitespace and final blank lines for diff hygiene;
source and artifact SHA-256 pins refer to the actual compiled inputs and binaries.
