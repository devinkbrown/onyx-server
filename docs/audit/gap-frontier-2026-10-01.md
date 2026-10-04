# Current foundational gap frontier

Baseline: `6b9759d9`. This is a sampled source/evidence audit, not an exhaustive
completion ledger for every historical roadmap heading. No deployment or push.

| Order / gap | Current evidence and remaining requirement |
|---|---|
| 1 — A11 / P0c / P11 ordinary presence | Direct identity and legacy ordinary DM both stop at one hop. [Active implementation audit](mesh-presence-2026-10-01.md). Require original signed identity, exact guest delivery, rename/quit/reuse, repair, OOM and Helix. |
| 2 — A2 cold mesh custody | RVG2/RVL2/RVO2 initialize empty on cold boot; required Helix snapshots exist. Require SIGKILL after upstream receipt while downstream remains owed, exact retained wire and replay retirement after cold restore. Helix evidence cannot prove this. |
| 2 — D1/D2 durable publication | Normal cold/Helix history and memos are tested. RAM publication can precede best-effort append. Require failed/ambiguous append then restart to prove accepted durable state survives. Do not silently substitute a tail-loss contract. |
| 3 — A9 global account directory | Services.reconcileDirectory has DST callers, no daemon/S2S caller found; nick and SCRAM/credential companion families are omitted. Require original signed ownership/conflict/delete semantics and atomic durable repair, then register once/authenticate elsewhere without MTOKEN/manual provisioning. |
| 4 — A3 independent same-account identities | Unique signed origin/account/nick on an unattached third node exists and has honest/forged DST coverage. Real independent tokens on two origins observed by a third remain separate from shared-token resume. Depends on directory/presence authority. |
| A10 lease timing | Live OFFER TTL protects logical presence after a late attachment lease. Require actual partition exceeding 90 seconds, no false QUIT/JOIN and original sockets alive, plus explicit detach/eventual OFFER expiry. |
| A4 Event Spine retirement | Cold history restoration exists; ESG2 replay authority initializes separately on cold boot. Require persistent retirement watermarks and replay after eviction/restart. |
| X1/X3/X4 platform coverage | Shared Linux/OpenBSD runtime has substantial native acceptance. FreeBSD/Windows remain minimal runtime/native primitives; Windows/full-runtime TLS benchmark cells remain unmeasured. Do not infer complete product ports from backend primitives. |
| K6/A6 interoperability | Remaining sampled cells include ECH+HRR, ChaCha-only HPKE, unsupported live armor s_client, BoGo skips and kernel bidirectional rekey. Require exact pinned independent interop/kernel evidence. |
| A1 OCG2 product evidence | Project/mint boot is now admitted. Reference TOML comments still describe historical rejection. Require configured live projection/mint/revoke/rollback and cold/Helix authority evidence. |
| A2 fleet activation | Compat remains default; activation plan/hot-downgrade guards exist. Deployment activation is unverified and requires explicitly authorized release after custody and topology gates. |

Do not reopen completed safety behavior based on historical wording: shared
configCheckError rejects unsafe SQPOLL+DEFER_TASKRUN and txrx; upgrade preflight
refuses listener changes; OCSP responder HTTPS verification is enabled. Ripple
is accurately described as a library and the daemon periodically re-bursts rosters.
Those facts do not close the missing multi-origin identity or durability contracts.

Source audit was read-only by the independent gate reviewer. No new runtime tests
were run for this table. Detailed acceptance must still be established requirement
by requirement; absent headings/checkmarks are not current source truth.

The [complete primary requirements inventory](gap-requirements-2026-10-01.json) extracts all 92 named roadmap outcomes (79 headings and 13 moonshot rows), their source ranges and explicit acceptance text, plus the 25 document cuts. It is a specification inventory, not a completion ledger: every outcome still needs current requirement-by-requirement evidence. This sampled frontier remains the execution order, not a substitute for the full scope.
