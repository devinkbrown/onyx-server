# Shared-IP mesh endpoint and lifecycle repair

Baseline: `d9991c00`. Final server candidate: `63bf1cb0`.
Status: final Linux and native acceptance complete.
No deployment or push. Preserve the unrelated roadmap `.save`.
Exact hashes, commands, reviews, failure history and results:
[acceptance record](evidence/mesh-endpoint-redial-2026-10-01/README.md).

## Root lifecycle invariant

An inbound source IP cannot prove a configured listener endpoint. A completed
outbound handshake now supplies canonical address, port and scope. Reciprocal
collapse transfers that binding only between identical authenticated secured
keys, independently of initiator direction and pending CONNECT storage. Helix
validates the existing carried address before mutation and publishes configured
dial bindings only after the full adoption transaction commits. No schema change.

Retiring a duplicate immediately revokes mesh admission and all connection-backed
authority. A shared ConnState eligibility rule governs routing, roster consumers,
active views, maintenance and replay. Every live application frame-family drain
requires the exact owning connection before consuming, and each receive driver
rechecks after every family. Retirement during deferred admission cannot publish
later MODE changes or encode SEARCH replies. Dial-success credit and SQUIT prefer
eligible peers; handshake cancellation remains an explicit separate fallback.

The retained duplicate exists only for lifecycle custody. Its bounded five-second
drain preserves the final HELLO or secured ciphertext until retained/backlog bytes
are empty and SEND ownership is released, or expiry/fault retires safely. Merely
queuing SEND does not count as transmission. Pressure retries, racing receive,
exact generation and kernel storage are preserved; incomplete drains refuse Helix.
Genuine netsplit cleanup and independently accepted signed stores keep their state.
The [286-function inventory](evidence/mesh-endpoint-redial-2026-10-01/lifecycle-consumer-inventory.md)
classifies active consumers and these exceptions rather than counting guards alone.

## Evidence and current acceptance

Fresh immutable-source production review found no blocker at `0323`. The final six
replay-fixture sections independently reverse to every byte of `0323`. Their actual
established link owners and declared capture sinks replace missing ownership and
fabricated SEND flags without weakening queue, AEAD, OOM, budget or cursor assertions.
Final combined Debug and ReleaseSafe each pass 145/145; check/fmt/diff pass.
Named server/services/Helix/mesh Debug and ReleaseSafe each pass 2354/2365
with 11 skips. Full Linux Debug and ReleaseSafe each pass 8845/8869
with 24 skips and all eight build steps successful.

Native OpenBSD Debug and ReleaseSafe each passed 108/109 selected module cases,
with one existing Linux-only arena skip. Both actual three-process reciprocal
campaigns passed all three real execs, 47 events / 225 exact deliveries, physical
socket/token continuity and durable cold authentication. Cumulative dial counts
remain unchanged over settled 22-second windows before/after and after each exec.
The final Debug artifact passed a fresh campaign; the final ReleaseSafe rebuild
is byte-identical to its accepted campaign. Final rebuilt runners pass in both
modes. Owned scratch VM/artifacts are cleaned, with both other VMs reachable.

The native shared-IP probe requires `--skip-partition`, because alias PF rules
cannot isolate same-address peers. Native socket tests separately prove close/heal.
Linux in-process Helix, native socket cases and real native exec remain distinct
scopes. Interrupted candidate waves never count as final acceptance.

## Remaining multi-hop presence frontier

Far-only ordinary unbound nickname/WHOIS/direct-message routing remains open in
an A-B-C line. Direct established rosters and membership bursts do not supply
signed original multi-origin presence; strict direct-origin validation correctly
rejects misattribution. Shared account/channel/session tests do not establish the
route to an independent far guest.

The next slice requires original signed presence with revisions/tombstones,
strict origin validation, transactional route/WHOIS publication, reconnect repair
and Helix continuity. Cover independent guests, rename/quit/collision identity,
allocation failure and mixed capabilities. Do not flood unknown messages or
re-author foreign membership claims as local.

An earlier baseline-identical reusable-session fixture produced one timestamp
mismatch. Targeted Debug/ReleaseSafe repetitions passed 72/72 and later runs passed;
its cause remains unproven. Exact timestamp assertions remain intact. This slice
does not close every roadmap gap or constitute production release acceptance.
