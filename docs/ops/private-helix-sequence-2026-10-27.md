# Private sequential Helix acceptance

The captured native Safe candidate preserves four TLS attachments through
sequential A-then-B same-process handoffs, then accepts a fifth attachment with
the original portable credential. Independent review verified the report,
artifact and helper hashes, source assertions, log filtering and cleanup.
This is bounded current-image acceptance, not historical-upgrade or release
acceptance.

| Phase | Application attachments | Cumulative accepted events | Exact recipient deliveries | Secured link establishments |
| --- | --- | --- | --- | --- |
| Before A | 4 | 9 | 41 | 1 per node |
| After A | 4 | 18 | 82 | 1 per node |
| After B | 4 | 27 | 123 | 1 per node |
| Fifth resume after B | 5 | 38 | 184 | 1 per node |

Four application TLS sockets are split two per node; observers/operators bring
the held-socket count to seven. The harness checks original socket FD/inode,
process PID/starttime/image, PONG, stable local token values, and exact
per-recipient channel/direct message IDs and timestamps. Each node records one
adoption. Final link counts are checked after owned processes stop, marker
filters drain and join, and filter errors are ruled out. Private temporary
config/key/account directories are removed; retained evidence contains no
bearer credentials or raw IRC payloads.

Artifact SHA-256:
`873b31540f4e0f512679a9612444656f767874c9ffefbd97a11aad4f6481d094`.
Report SHA-256:
`6c71c830862df89f1275803aede469bbb40a28c144774b522d79a4990aa85235`.

Reproduction uses the cache adapter and reviewed dependencies:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B .zig-cache/wave-8/linux-helix-sequence-v2/adapter.py --binary /absolute/captured/candidate --expected-sha256 <artifact-sha256> --evidence-dir /new/private/evidence-directory
```

The adapter/dependency hashes and the completed `run-01/result.json` and
sanitized marker logs are in `.zig-cache/wave-8/linux-helix-sequence-v2/`.
The source artifact predates the 186-file compiler-format migration. Its
runtime result does not certify the rewritten source bytes. The pilot uses
SIGUSR2 and legacy portable issuance (`resume_composite_issuance=false`), not
operator UPGRADE authorization or SRM2. It covers two private loopback nodes,
not three-node/non-clique or distinct-host deployments. No live service was
modified.

The historical image has a separate
[handoff compatibility constraint](upgrade-compatibility-2026-10-27.md).


## Three-node non-clique extension

A subsequent reviewed private run used A–B–C, with no A–C link. Four TLS
application attachments were placed two on A, one on B and one on C; the
observer lived on C. Sequential A then B handoffs retained their original
process identities and both client-side and actual daemon-owned accepted
socket FD/inode identities. A fifth client on C resumed using the original
portable credential after both handoffs. Exact channel/direct event and
recipient checks reached the same cumulative 38 events and 184 deliveries.
Secured link establishments remained **1/2/1**, and final adoption counts were
**1/1/0**, checked after process cleanup and marker-filter drain. Independent
review accepted the bounded evidence and cleanup.

The first two attempts failed before upgrade checks in the helper's socket
census. The daemon's dual-stack accepted sockets appeared in `tcp6`, whereas
the original census read only `tcp`. The correction decodes IPv4 and IPv6
native-word representations, normalizes mapped IPv4 addresses, and still
requires the exact reversed endpoint tuple, one established inode and one
process-owned FD. Six pure parser tests cover endian variants, wrong tuple,
state and ambiguity. No protocol, Oracle, deadline or custody assertion was
relaxed; earlier failures remain recorded.

Evidence: `.zig-cache/wave-8/linux-helix-nonclique-v3/`, including the pinned
adapter/dependencies, parser tests and `run-01/result.json`.
Report SHA-256: `510886deb427cf6f225d8ce83db5d5fa9a7c0c7937b15302343db702ef6490a2`.
The binary remains the captured `873b…` artifact named above; all historical,
post-format source, SRM2, operator-command and distinct-host limitations still
apply. This extends private same-image topology coverage; it does not accept
M11's larger simulation/deployment campaign or certify a release.


## Four-node diamond extension

The reviewed four-node pilot used only A–B, A–C, B–D and C–D links. Each node
held one application attachment; the observer lived on D. All four nodes then
adopted the same image sequentially, A through D, while every original client
and daemon-owned accepted socket retained its identity. A fifth attachment on
D resumed using the original portable credential after the last handoff.
Strict cumulative checks reached **56 events and 266 exact deliveries** over
six phases. Final drained logs show two secured link establishments and one
adoption per node. Independent review verified hashes, the unchanged recipient,
msgid/time oracle, completed cleanup and absence of retained private processes.

The initial diamond attempt failed configuration preflight because its trust
roots included each node's own key, violating the existing duplicate-identity
validation. The correction gives each node its two actual neighbors as direct
trust roots while retaining a separate four-member relay-author roster. No
validator, protocol, custody or delivery assertion was weakened. The failed
attempt remains recorded separately.

Evidence: `.zig-cache/wave-9/linux-helix-diamond-v2/run-01/result.json` and its
pinned adapter/dependency manifest. Report SHA-256: `e70d11a08621f196bfa385f4cb06edcddb37418762bb3d5629df8895a37ccde3`.
The artifact remains captured `873b…`, before the compiler-format migration.
These four local same-image handoffs do not prove historical upgrades, SRM2,
operator-command authorization, distinct-host deployment, fault campaigns or
8/32/128-node simulation acceptance. T02 and M11 remain partial.


## Current-source confirmation

After guarded wave9 source integration, artifact
`43d703c0466ad1945f43b8765e338f41c4339997eb791f72ecd5a91a646b9a81`
matched all 1,219 current inputs. The unchanged diamond helper passed again:
56 events / 266 exact deliveries, sequential A/B/C/D adoptions, fifth resume,
retained physical sockets, final links 2/2/2/2 and adoptions 1/1/1/1. Independent
review verified pins and cleanup. Evidence:
`.zig-cache/wave-9/linux-helix-diamond-v2/current-source-01/result.json`.

This closes the compiler-format migration's runtime gap for this private
same-image Linux/legacy-portable scenario. Historical compatibility, SRM2,
operator-triggered upgrades, distinct hosts and active media continuity remain
separate requirements. The previous complete suite is red and wave10 remains
unpromoted; this confirmation does not certify a release.
