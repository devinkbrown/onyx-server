# Historical handoff compatibility constraint

Read-only comparison of historical source `ae78d490` with the current source
finds no client/TLS capsule version overlap:

| Capsule | Historical source | Current source |
| --- | --- | --- |
| Clients | Exact version 5 | Exact version 7 |
| TLS sessions | Versions 1–2 | Exact version 3 |

Negotiation rejects unsupported versions. This is source evidence about a
historical commit, not a statement of what either live node currently runs.
The successful private current-image sequence does not establish a seamless
upgrade from that historical image. Current decoding remains strict.

An intermediate executable accepting the old formats cannot generally recover
facts already discarded by the first historical export. The old TLS engine
stores negotiated record limits, ALPN and exporter state, but its serializer
omits required facts, including the exporter secret. Application traffic
secrets do not generally recover that secret. Maximum record limits and absent
ALPN are not historical-engine guarantees. Client v5 also omits required
trusted effective peer/accounting ownership, FloodGuard debt/policy and several
attachment policies and clone/throttle ownership facts.

A universal bridge therefore needs an established, authorized way to capture
exact missing facts before the old process discards them. No such mechanism is
established by this audit. Renaming a legacy decoder as a native bridge, filling
in defaults, restricting the state subset, or reconnecting attachments does
not satisfy the universal preservation contract. No bridge is implemented or
accepted here.

Separate gates remain necessary:

- Current-image sequential preservation: the bounded private two-node pilot
  has passed on its recorded pre-format artifact.
- Historical refusal and rollback: preserve held attachments when attempting
  an incompatible image; actual historical-image runtime acceptance remains
  unverified.
- Any proposed bridge: adversarial old blobs with differing omitted state,
  exact physical-identity joins and cryptographic custody, followed by a real
  old-to-bridge-to-current sequence without attachment reconnection.

Detailed field/source findings and the read-only audit are retained in
`.zig-cache/wave-8/compatibility-bridge-source-audit.txt`. Deployment planning
must inspect the actual source artifact and configuration at that time. No
runtime migration, instrumentation, restart or deployment was performed by
this audit.


## Account-host provenance boundary

A separate 2026-10-29 source audit found that the pre-HPR1 client image carries
the visible host without recording whether it was generated or explicitly
assigned. Bare operator VHOST does not create Guise provenance, and a failed
best-effort Guise persistence attempt can leave accepted RAM state absent from
the successor's durable registry. Registry absence and hostname syntax therefore
cannot establish that a carried host is safe to replace.

W55 fixes fresh account-cloak generation and replacement, with actual SACCESS
privilege regressions passing Debug and Safe. It does not repair an already-wrong
host restored from an older image. W56 is implementing mandatory physical host
provenance and staged adoption corrections. Its source-reviewed HPR1 codec
preserves the existing 255-byte host contract, including high bytes; Core and
runtime acceptance remain in progress.

The new boundary must reject missing or ambiguous mandatory intent before exec,
leaving the source serving its existing clients. Supported generated-host repair
must preserve old accepted bytes, then publish one ordered host change before
new-host traffic; explicit operator/persona intent requires positive carried
provenance. There is no accepted universal reconstruction of intent omitted by
an older source image, and no historical migration or deployment was performed
by this work.
