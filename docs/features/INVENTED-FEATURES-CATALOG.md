# Onyx Server — invented feature catalog

*A speculative, source-grounded catalog of features the daemon does **not** have
today. Written by `stack-architect` as design input, not as a commitment.*

Companion to [`docs/ROADMAP-2026-Q4.md`](../ROADMAP-2026-Q4.md). The roadmap
tracks **S-01 … S-30** — subsystems that exist and need finishing. This document
is the other half: **F-01 … F-68**, things that do not exist at all and that the
existing substrate makes unusually cheap to build.

Daemon at time of writing: **0.5.8**, 842 Zig files, ~590k lines, ~180 commands
across 13 dispatch modules (`src/daemon/modules/`).

---

## How this was grounded

Every "Onyx Server does not have X" claim below was checked against HEAD before it was
written. Several candidate features were **cut during the survey** because they
already ship — recorded here so nobody re-invents them:

| Candidate cut | Already exists at |
| --- | --- |
| Message reactions | Typed CRDT model — `src/proto/activity.zig:4-14`, `draft/react` cap at `src/proto/cap.zig:43,408`, live push via `src/daemon/activity_subscriptions.zig:4-9` |
| Typing / presence stream | Same activity plane, `ACTIVITY SUBSCRIBE` |
| Channel polls | `src/daemon/poll.zig:3-5` — bounded options, voter state, tally |
| Live call captions | `src/daemon/transcript.zig:3-8` — speaker-tagged ring, `MEDIA TRANSCRIPT` |
| Signed moderation proofs | `src/daemon/proofmark.zig:3-9` — actor/action/target/policy-version/reason-digest, stable binary transcript |
| Structured announcements | `src/daemon/announce_board.zig:3-8` — scoped, categorized, expiring, dismissible |
| Virtual-host wardrobe | `src/daemon/guise.zig:3-9` — generalized identity wardrobe, not a flat vhost pool |
| Incoming Discord-format webhooks | `src/daemon/webhook.zig:4-8` + `webhook_http.zig:4-12` + `webhook_render.zig:4-11` |
| Content filtering | `src/daemon/content_filter.zig:3-8` (Koshi, Aho-Corasick) |
| Decaying IP reputation | `src/daemon/ip_reputation.zig:3-8` |
| Connection classes / admission | `[class.*]` in `etc/onyx-server.reference.toml:473-478` |
| Timestamped backups | `[backup]` at `etc/onyx-server.reference.toml:849-853` |
| New-user onboarding pack | `src/daemon/welcome_pack.zig:3-8` |
| Offline memos + grouped nicks | `src/daemon/memo_group.zig:3-6` |
| Cron expression parsing | `src/substrate/cron.zig:3-7` — parser exists, **no scheduler consumes it** (see F-52) |

**Confirmed absent** at HEAD (no source hit for the concept as a first-class
feature): slowmode, threads-as-objects, scheduled/deferred messages, human
verification, protocol bridges, translation, moderation appeals, retention
policy, per-account (as opposed to per-connection) abuse scoring, outbound
webhooks, histogram metrics, distributed tracing export.

---

## Legend

- **Complexity** — `S` (days) · `M` (1–2 weeks) · `L` (a month) · `XL` (a quarter+)
- **Priority** — `P0` should be in 0.7 · `P1` 0.7 if there is room · `P2` later
- **Novelty** — `★☆☆` incremental (other daemons have it) · `★★☆` differentiated
  (exists elsewhere, but Onyx Server's substrate makes it materially better) ·
  `★★★` genuinely novel (no IRC daemon does this; no chat platform does it this way)
- **Client** — `none` daemon-internal · `gated` a client can consume it as-is ·
  `contract` needs a coordinated wire change (see [Wire contract discipline](#wire-contract-discipline))

---

## Top 20 game-changers for 0.7

Ranked by *(operator value × novelty) / cost*, filtered to things that are
buildable on the substrate that already exists.

| # | Feature | One-line pitch | Cx | Novelty | Client |
| --- | --- | --- | --- | --- | --- |
| **1** | [F-39 Deep metrics](#f-39--deep-metrics-histograms-not-just-counters) | Ten scalar counters become a real observability surface with latency histograms | M | ★★☆ | none |
| **2** | [F-15 Account trust ledger](#f-15--account-trust-ledger) | Abuse score that survives reconnect — the axis `flood_guard` explicitly refuses to model | M | ★★★ | gated |
| **3** | [F-52 Scheduled & deferred delivery](#f-52--scheduled--deferred-delivery) | `cron.zig` already parses the expression; nothing fires it | M | ★★☆ | contract |
| **4** | [F-08 Proofmark federation](#f-08--proofmark-federation-portable-moderation-receipts) | Signed moderation proofs become mesh-portable and independently verifiable | L | ★★★ | gated |
| **5** | [F-24 Outbound event webhooks](#f-24--outbound-event-webhooks) | Webhooks are incoming-only today; make the Event Spine push out | M | ★☆☆ | none |
| **6** | [F-16 Graduated slowmode](#f-16--graduated-slowmode-with-automatic-relief) | Per-channel rate ceiling that engages on raid detection and relaxes on its own | S | ★★☆ | contract |
| **7** | [F-46 Preflight doctor](#f-46--onyx-doctor--preflight-and-live-health-audit) | One command that tells an operator exactly why their self-host is unhealthy | M | ★★☆ | none |
| **8** | [F-53 Threads as first-class objects](#f-53--threads-as-first-class-objects) | `draft/reply` exists as a tag; make the thread an addressable object with stable keys | L | ★★☆ | contract |
| **9** | [F-40 Flight-recorder export](#f-40--flight-recorder-export-on-fault) | `qlog`/`trace` keep the last N events — dump them on the fault that matters | S | ★★☆ | none |
| **10** | [F-17 Progressive challenge ladder](#f-17--progressive-challenge-ladder) | A suspicious connection is challenged, not refused — pluggable, no third-party captcha | M | ★★☆ | contract |
| **11** | [F-09 Cross-node oper console](#f-09--mesh-wide-oper-console-with-origin-attribution) | Extends S-03: one oper session sees every node's verdicts, attributed | M | ★★☆ | contract |
| **12** | [F-59 Retention policy engine](#f-59--per-channel-retention-policy-engine) | Per-channel "forget after N days" enforced by the daemon, not by hoping | M | ★★☆ | gated |
| **13** | [F-25 Bot capability grants](#f-25--scoped-bot-capability-grants) | Bots get scoped, expiring, auditable capability tokens instead of oper-or-nothing | M | ★★☆ | contract |
| **14** | [F-41 Per-command telemetry](#f-41--per-command-cost-telemetry) | `command_usage.zig` counts; add cost so an operator can find the expensive command | S | ★☆☆ | none |
| **15** | [F-32 Recording with consent gate](#f-32--consent-gated-call-recording) | Call recording that is cryptographically impossible without visible consent | L | ★★★ | contract |
| **16** | [F-47 Config wizard + dry-run diff](#f-47--config-wizard-and-rehash-dry-run-diff) | `--check-config` says valid/invalid; show what a REHASH would actually change | S | ★★☆ | none |
| **17** | [F-18 Raid-shape detector](#f-18--raid-shape-detector) | Correlate join patterns across the mesh — catch the raid the per-IP limiter misses | L | ★★★ | none |
| **18** | [F-60 Sealed rooms](#f-60--sealed-rooms-metadata-minimal-channels) | A channel whose membership the daemon itself cannot enumerate | XL | ★★★ | contract |
| **19** | [F-26 Extension sandbox v1](#f-26--wasm-extension-sandbox-for-policy-hooks) | The `wasm/` tree becomes a policy hook point with a fuel budget | L | ★★☆ | none |
| **20** | [F-10 Authority projection rehearsal](#f-10--ocg2-projection-rehearsal-mode) | Rehearse OCG2 `project` against live traffic without applying it — unblocks S-05 | M | ★★☆ | none |

**If you only do three:** F-39 (you cannot operate what you cannot see),
F-15 (the one anti-abuse axis the daemon consciously left open), and F-52 (the
substrate is already written).

---

## A — Operator & network governance

Onyx Server already carries ~48 oper commands (`src/daemon/modules/oper_security.zig`,
`services_ext.zig`). These are the governance primitives that are still missing.

### F-01 — Policy-as-configuration with versioned rollback
**Pitch:** every moderation setting (wards, filters, classes, limits) gets a
version number, a diff, and a one-command rollback.
**Why:** an operator who tightens a ward at 3am and locks out half the network
currently has no "undo" — they must remember what the file said. `proofmark.zig`
already carries a `policy version` field in its signed transcript
(`src/daemon/proofmark.zig:5-6`), so the concept exists but nothing produces the
version it references.
**Home:** `src/daemon/policy_version.zig` (new), `config_boot.zig`
**Owner:** onyx-server-config · **Cx:** M · **Deps:** — · **P1** · **★★☆** · client: none

### F-02 — Two-person rule for destructive operator actions
**Pitch:** `DIE`, `RESTART`, mesh-scope `KLINE`, and `DROP` optionally require a
second operator's confirmation inside a time window.
**Why:** a compromised oper account is the highest-blast-radius credential on the
network. The daemon already has `oper_session_provenance.zig` and
`durable_oper_authority.zig` — it knows who is who — but a single session can
still `DIE` the node.
**Home:** `src/daemon/oper_quorum.zig` (new), `modules/oper_security.zig`
**Owner:** zig-coder · **Cx:** M · **Deps:** F-01 · **P1** · **★★☆** · client: gated

### F-03 — Scheduled operator actions
**Pitch:** `KLINE ... AT 2026-01-01T00:00Z` / `TEMPMODE ... UNTIL` — set it now,
fire later, survives USR2.
**Why:** operators plan maintenance windows and event lockdowns. Today they set
an alarm and do it by hand. `cron.zig` parses the expression already.
**Home:** `src/daemon/action_schedule.zig` (new) + a Helix capsule
**Owner:** zig-coder · **Cx:** M · **Deps:** F-52 scheduler core · **P2** · **★☆☆** · client: gated

### F-04 — Operator runbooks as executable macros
**Pitch:** a named, parameterized, audited sequence of oper commands — `RUNBOOK RUN raid-lockdown #chan`.
**Why:** incident response is currently muscle memory. A runbook is reviewable
before the incident and auditable after it, and it removes the "which order do I
do these in" failure mode at 3am.
**Home:** `src/daemon/runbook.zig` (new)
**Owner:** zig-coder · **Cx:** M · **Deps:** F-01 · **P2** · **★★☆** · client: gated

### F-05 — Moderation appeal channel
**Pitch:** a banned user gets a structured, rate-limited appeal path instead of a
closed socket.
**Why:** every ban is currently terminal from the user's side. An appeal record
keyed to the `proofmark` of the original action gives the operator context and
the user a process — and it produces the data to find over-broad wards.
**Home:** `src/daemon/appeal.zig` (new) + `warden.zig` `quarantine` action
(`src/daemon/warden.zig:82`), which already permits a restricted connection
**Owner:** onyx-server-warden · **Cx:** M · **Deps:** proofmark · **P2** · **★★☆** · client: contract

### F-06 — Delegated channel operator roles
**Pitch:** named roles with capability subsets (`can_kick`, `can_topic`,
`can_invite`) instead of the binary `+o`.
**Why:** IRC's op model is all-or-nothing; a trusted greeter should be able to
`INVITE` without being able to `KICK`. `scoped_access.zig:3-6` already stores
ordered grants *and* restrictions — the storage exists, the role vocabulary does not.
**Home:** `src/daemon/channel_role.zig` (new), `scoped_access.zig`
**Owner:** onyx-server-ircx · **Cx:** L · **Deps:** — · **P1** · **★★☆** · client: contract

### F-07 — Network constitution document
**Pitch:** a signed, versioned, mesh-replicated policy document every node serves
and every client can fetch and verify.
**Why:** on a federated mesh, "what are this network's rules" has no canonical
answer. Signing it means a node cannot quietly serve different rules than its peers.
**Home:** `src/daemon/constitution.zig` (new), replicated as an Undertow LWW record
**Owner:** onyx-server-mesh · **Cx:** M · **Deps:** mesh CRDT · **P2** · **★★☆** · client: contract

---

## B — Federation, mesh & cross-node authority

The mesh substrate is deep — `merkle.zig`, `prolly.zig`, `riblt.zig`,
`delta_codec.zig`, `convergence.zig`, `partition_detector.zig`, Ripple witnessed
failure detection. These features spend that substrate on product surface.

> **Guard rail — every feature in this section.** Any periodic task added here
> must name a **single owning reactor** (`if (self.rx() != &self.reactors[0]) return;`
> — the pattern at `src/daemon/server.zig:5163,5259`). A sibling reactor with no
> peer links otherwise wins the guard and does nothing, which is exactly the
> failure that reaped live peers past their TTL. And liveness refresh stays
> **orthogonal** to value LWW: a "still here" update is never gated on a newer HLC.

### F-08 — Proofmark federation: portable moderation receipts
**Pitch:** a moderation proof issued on node A verifies on node C without
trusting node B, and a user can carry a receipt for an action taken against them.
**Why:** this is the single highest-novelty thing the tree is already 60% set up
for. `proofmark.zig:3-9` produces a signed, fixed-order, length-prefixed
transcript that is stable across machines and restarts — that is precisely a
portable receipt. What is missing is replication, a verification command, and a
revocation path. Federated moderation today (Matrix, ActivityPub) is a trust
mess; a verifiable receipt is a real answer.
**Home:** `src/daemon/proofmark.zig`, `src/substrate/undertow/` (new record kind)
**Owner:** onyx-server-mesh · **Cx:** L · **Deps:** mesh CRDT, signed_frame ·
**P0** · **★★★** · client: gated
**Invariant:** mesh identity on the issuing link is the `shortId`, never nick/UID.

### F-09 — Mesh-wide oper console with origin attribution
**Pitch:** the S-03 Event Spine v2, plus per-event origin node, plus a
`bounded replay` on subscribe.
**Why:** the roadmap's S-03 accept criteria already demand cross-node delivery.
This adds the operator-facing half: attribution (which node decided this), and a
join-time replay window so an operator who connects mid-incident sees the last
N minutes rather than starting blind.
**Home:** `src/daemon/event_spine.zig`, `event_history.zig`
**Owner:** onyx-server-ircx · **Cx:** M · **Deps:** S-03 · **P0** · **★★☆** · client: contract

### F-10 — OCG2 projection rehearsal mode
**Pitch:** a fourth OCG2 stage between `observe` and `project` that computes
every privilege change against live traffic and **reports the diff without applying it**.
**Why:** S-05 is P1 and stalled because `project` is a one-way door — the build
currently fails boot in that mode by design. Rehearsal makes the transition
evidence-based: an operator runs it for a week, reads "these 14 sessions would
have gained/lost authority," and flips the switch knowing what happens.
**Home:** `src/daemon/ocg2_projection_runtime.zig`
**Owner:** zig-coder · **Cx:** M · **Deps:** S-05 · **P0** · **★★☆** · client: none

### F-11 — Selective federation (per-peer policy contracts)
**Pitch:** a node declares what it accepts from each peer — channels, ward
scopes, account authority — instead of all-or-nothing linking.
**Why:** today linking is a full trust decision. Selective federation lets a
small node join a large mesh for message routing without importing its ban list
or accepting its account authority. This is the feature that makes hosting your
own node politically viable.
**Home:** `src/daemon/peer_policy.zig` (new), `secured_s2s_link.zig`
**Owner:** onyx-server-mesh · **Cx:** L · **Deps:** — · **P1** · **★★★** · client: none
**Fail-closed:** an unrecognized policy token from a peer means **reject the
frame class**, never "accept because we could not parse the restriction."

### F-12 — Mesh capability negotiation
**Pitch:** peers exchange a feature vector at link time; a frame class no peer
understands is never emitted onto that link.
**Why:** rolling upgrades across a mesh currently rely on capsule versioning
(Helix) for state and on hope for wire frames. An explicit negotiated vector
makes a mixed-version mesh a designed state rather than an accident.
**Home:** `src/substrate/undertow/link_session.zig`, `signed_frame.zig`
**Owner:** onyx-server-mesh · **Cx:** M · **Deps:** — · **P0** · **★★☆** · client: none

### F-13 — Geographic routing hints
**Pitch:** route a cross-node message along the lowest-latency path using
observed link RTT rather than the first available hop.
**Why:** `link_health.zig` and the RTT samples at `src/daemon/server.zig:6230`
already measure this; `route_table.zig` does not spend it. On a
geographically-spread mesh this is a direct latency win with no new measurement.
**Home:** `src/substrate/undertow/route_table.zig`, `mesh_topology.zig`
**Owner:** onyx-server-mesh · **Cx:** M · **Deps:** S-09 · **P2** · **★★☆** · client: none

### F-14 — Read-only observer nodes
**Pitch:** a node that receives mesh state and serves clients but is not
authoritative for anything and cannot originate state.
**Why:** the cheapest path to geographic scale and to community-run edge nodes.
An observer can be run by someone you trust less than a full peer, because the
worst it can do is serve stale data. Pairs with F-11 and F-68.
**Home:** `src/substrate/undertow/s2s_peer.zig`, `mesh.zig`
**Owner:** onyx-server-mesh · **Cx:** L · **Deps:** F-11, F-12 · **P2** · **★★☆** · client: none

---

## C — User safety & anti-abuse

Existing: `warden.zig` (8 match types, node/mesh scope, 4 actions),
`flood_guard.zig`, `clone_detect.zig`, `clone_limit.zig`, `shun.zig`,
`spamtrap.zig`, `ip_reputation.zig`, `dnsbl.zig`, `content_filter.zig`,
`gag_set.zig`, `cooldown.zig`. The gaps below are the axes those modules
deliberately do not cover.

### F-15 — Account trust ledger
**Pitch:** a decaying, mesh-replicated abuse/trust score keyed to the **account**,
not the connection — the axis `flood_guard` explicitly declines to model.
**Why:** `src/daemon/flood_guard.zig:22-24` says it outright: *"This guard is
strictly per-connection … A per-account abuse score that survived reconnects
would be a separate axis; this module does not model it."* That is the single
most-quoted gap in the tree. An abuser who reconnects gets a clean slate today.
`ip_reputation.zig:3-8` proves the decay math works; this applies it to a durable
identity, which is both fairer (IP reputation punishes NAT neighbours) and harder
to evade.
**Home:** `src/daemon/account_trust.zig` (new), replicated as a CRDT counter
(`src/substrate/crdt_counter.zig`)
**Owner:** onyx-server-warden · **Cx:** M · **Deps:** mesh CRDT ·
**P0** · **★★★** · client: gated
**Invariant:** score is advisory input to a policy decision, never an automatic
ban — and it decays, so a reformed account recovers.

### F-16 — Graduated slowmode with automatic relief
**Pitch:** per-channel minimum interval between messages that **engages on
detected pressure and relaxes on its own**, rather than being an op's manual toggle.
**Why:** Discord's slowmode is manual and blunt; the value is in the automation.
The daemon already computes flood verdicts per connection — aggregating them per
channel gives an engage signal for free, and the relief timer means an op does
not have to remember to turn it off.
**Home:** `src/daemon/slowmode.zig` (new), a new `chanmode_ext` letter
(see [Wire contract discipline](#wire-contract-discipline) for the free-letter set)
**Owner:** onyx-server-warden · **Cx:** S · **Deps:** flood_guard · **P0** · **★★☆** · client: contract

### F-17 — Progressive challenge ladder
**Pitch:** a suspicious connection is progressively challenged — delay, then
proof-of-work, then account requirement — instead of being refused outright.
**Why:** `warden.Action` has exactly four outcomes today
(`src/daemon/warden.zig:79-92`): refuse, expel, quarantine, require_auth. All are
terminal or binary. A ladder converts a false positive from "you are banned" into
"this took you four seconds." Proof-of-work keeps it self-contained — no
third-party captcha service, which matters for a self-hostable AGPL daemon.
**Home:** `src/daemon/challenge.zig` (new), `warden.zig` new Action variant
**Owner:** onyx-server-warden · **Cx:** M · **Deps:** F-15 · **P0** · **★★☆** · client: contract

### F-18 — Raid-shape detector
**Pitch:** correlate join timing, nick morphology, and connection fingerprints
**across the mesh** to detect a coordinated raid that no single per-IP limiter sees.
**Why:** `clone_detect.zig` and `mesh_clones.zig` find the same *user* twice. A
raid is 200 *different* users arriving in 30 seconds with correlated
characteristics. The substrate for this is already sitting there unused:
`minhash.zig`, `count_min_sketch.zig`, `topk.zig`, `hyperloglog.zig`,
`levenshtein.zig`. This is a genuinely novel primitive for an IRC daemon.
**Home:** `src/daemon/raid_detect.zig` (new)
**Owner:** onyx-server-warden · **Cx:** L · **Deps:** F-15, mesh · **P1** · **★★★** · client: none
**Guard rail:** the correlation window is a periodic task — it must be
reactor-0-gated or provably reactor-local.

### F-19 — Per-channel quarantine rooms
**Pitch:** a quarantined user is moved to a shadow view of the channel where
they can see and speak but their messages reach only operators.
**Why:** `warden.Action.quarantine` exists (`warden.zig:82`) but restricts to
"no join/speak." A shadow room is strictly better against a determined abuser:
they see no evidence of being blocked, so they do not immediately re-register.
**Home:** `src/daemon/quarantine_view.zig` (new), `world_projection.zig`
**Owner:** onyx-server-warden · **Cx:** M · **Deps:** — · **P1** · **★★☆** · client: none

### F-20 — Cross-channel ban import with attribution
**Pitch:** a channel op may subscribe to another channel's ban list, with the
source visible and one-click divergence.
**Why:** small communities re-do the same moderation work. Subscription with
attribution keeps autonomy (you can always diverge) while sharing the labour, and
attribution stops the trust-laundering problem that kills shared blocklists.
**Home:** `src/daemon/ban_subscribe.zig` (new), `scoped_access.zig`
**Owner:** onyx-server-warden · **Cx:** M · **Deps:** F-08 · **P2** · **★★☆** · client: contract

### F-21 — First-message screening
**Pitch:** a new account's first N messages in a channel are held for op review
or subjected to stricter filtering.
**Why:** almost all spam arrives in an account's first minute. Screening exactly
that window costs legitimate users one held message and destroys the drive-by
spam economy. `content_filter.zig` is the matcher; the missing part is the
"account age in this channel" gate.
**Home:** `src/daemon/first_contact.zig` (new)
**Owner:** onyx-server-warden · **Cx:** S · **Deps:** F-15 · **P1** · **★★☆** · client: contract

### F-22 — User-side safety controls
**Pitch:** per-user, server-enforced filters — block unregistered DMs, require
account age, mute by pattern — that follow the account across devices.
**Why:** `SILENCE` and `gag_set.zig` are per-connection and coarse. Moving this
to the account makes it survive reconnect and sync to a second device, and it
moves safety from "your client hides it" to "the server never sends it," which is
the only version that works against a hostile client.
**Home:** `src/daemon/user_policy.zig` (new)
**Owner:** onyx-server-ircx · **Cx:** M · **Deps:** — · **P1** · **★★☆** · client: contract

### F-23 — Abuse-report pipeline
**Pitch:** `REPORT <target> <reason>` produces a structured, deduplicated,
evidence-attached case that lands in the operator console.
**Why:** reporting is currently "find an op and describe it." A structured report
with the message id attached means the operator sees the actual evidence, and
deduplication turns 40 reports of one incident into one case with a count.
**Home:** `src/daemon/report_case.zig` (new), Event Spine `policy` category
(`src/daemon/event_spine.zig:23`)
**Owner:** onyx-server-ircx · **Cx:** M · **Deps:** F-09 · **P1** · **★★☆** · client: contract

---

## D — Developer & integrator platform

Existing: incoming Discord-compatible webhooks (`webhook.zig`, 1298 lines),
`bot_registry.zig`, the `wasm/` tree, `OROWASM` introspection command.

### F-24 — Outbound event webhooks
**Pitch:** the Event Spine posts to an operator-configured URL with retry,
backoff, HMAC signing, and a dead-letter queue.
**Why:** webhooks today are strictly **incoming** (`webhook_http.zig:4-12` is a
listener; `http_fetch.zig:4-6` is a GET-only client for the weather fetcher).
There is no way to get an Onyx Server event into an external system without polling.
Every integration story — PagerDuty, a moderation dashboard, an audit sink —
starts here. `circuit_breaker.zig` and `backoff.zig` already exist in substrate.
**Home:** `src/daemon/webhook_out.zig` (new), on the `geo_services` background-thread
pattern (`src/daemon/geo_services.zig:3-8`) so it never touches reactor io_uring
**Owner:** zig-coder · **Cx:** M · **Deps:** — · **P0** · **★☆☆** · client: none
**Fail-closed:** an unreachable sink must degrade to the dead-letter queue with a
bounded size, never grow unboundedly and never block a reactor.

### F-25 — Scoped bot capability grants
**Pitch:** a bot receives a signed, expiring token carrying exactly the
capabilities it needs, revocable without touching the account.
**Why:** `bot_registry.zig:3-8` tracks recognition and announcement scope; beyond
that a bot needing privilege needs oper, which is absurd for a dice bot. Scoped
grants also make a compromised bot a bounded incident.
**Home:** `src/daemon/bot_grant.zig` (new), `scoped_access.zig`
**Owner:** onyx-server-ircx · **Cx:** M · **Deps:** F-06 · **P0** · **★★☆** · client: contract

### F-26 — WASM extension sandbox for policy hooks
**Pitch:** operators load a WASM module that observes and can veto specific
events (join, message, nick change) under a hard fuel and memory budget.
**Why:** the `wasm/` tree and `[wasm]` config exist; the daemon has no extension
point at all today, so every network wants a patch. A fuel-metered sandbox is the
safe version — it cannot allocate unboundedly, cannot block a reactor, and cannot
reach the network.
**Home:** `src/wasm/host/`, `src/daemon/extension_hook.zig` (new)
**Owner:** zig-coder · **Cx:** L · **Deps:** — · **P1** · **★★☆** · client: none
**Fail-closed:** a hook that exhausts its fuel budget or traps is **skipped**, and
the default policy applies — an extension can never fail a decision *open*.

### F-27 — Structured rich messages
**Pitch:** a typed, capability-gated structured payload (heading / fields /
actions) that degrades to plain text for clients that do not negotiate it.
**Why:** the BlockKit-style primitive for IRC. The load-bearing design decision is
that the daemon stores and relays **typed tokens**, never markup — which keeps
the client's XSS sink closed by construction, because there is no HTML anywhere
in the pipeline.
**Home:** `src/proto/rich_message.zig` (new)
**Owner:** onyx-server-ircx · **Cx:** L · **Deps:** — · **P1** · **★★☆** · client: contract
**Invariant:** parse → typed tokens → text nodes. No markup, no HTML, ever.

### F-28 — Interactive message actions
**Pitch:** a message can carry buttons that dispatch a callback to the owning bot.
**Why:** turns bots from text parsers into applications, without inventing a
second protocol. Depends entirely on F-27's typed model.
**Home:** `src/proto/rich_message.zig`, `bot_registry.zig`
**Owner:** onyx-server-ircx · **Cx:** M · **Deps:** F-27, F-25 · **P2** · **★★☆** · client: contract

### F-29 — Slash-command registry
**Pitch:** bots register namespaced commands with typed parameters, discoverable
via a query command and advertised to clients.
**Why:** discovery is the missing half of every bot ecosystem — today a user has
to know the syntax. A registry gives clients real autocomplete and gives the
daemon a place to rate-limit per command.
**Home:** `src/daemon/command_registry.zig` (new)
**Owner:** onyx-server-ircx · **Cx:** M · **Deps:** F-25 · **P1** · **★★☆** · client: contract

### F-30 — Protocol bridge framework
**Pitch:** a general adapter for relaying to/from another protocol (Matrix, XMPP,
Discord) with identity mapping and loop prevention.
**Why:** the incoming webhook path already proves the sanitisation discipline
(`webhook_render.zig:4-11` scrubs every control byte and CR/LF before it can
reach the wire). A general bridge is that plus identity mapping, echo
suppression, and a per-bridge trust boundary. This is a network-growth feature.
**Home:** `src/daemon/bridge/` (new)
**Owner:** zig-coder · **Cx:** XL · **Deps:** F-24 · **P2** · **★★☆** · client: gated
**Invariant:** every byte from a bridge is untrusted input, sanitised exactly as
webhook payloads are — a bridge is not a peer.

### F-31 — Read-only HTTP query API
**Pitch:** a small authenticated JSON API for channel lists, member counts, and
public metadata — for status pages and directories.
**Why:** `status.json` (`src/daemon/server.zig:6855-6863`) is a single static
file. A minimal query API is what a community website actually needs, and it
already has the right shape to copy: loopback-by-default threaded listener
(`metrics_http.zig:6-21`).
**Home:** `src/daemon/query_http.zig` (new)
**Owner:** zig-coder · **Cx:** M · **Deps:** — · **P2** · **★☆☆** · client: none

---

## E — Media & voice

Existing: `media_plane.zig` (SFU + live UDP + DTLS 1.2/1.3 terminators),
`media_bridge.zig`/`causeway.zig` (native ⟷ WebRTC rewrap), `sfu_srtp.zig`,
`transcript.zig`. `simulcast_select.zig` **is** wired — `MEDIA ABR` runs
`selectStable` over a fixed three-layer ladder (`src/daemon/server.zig:203,46395-46411`),
which is exactly the "static rung" S-16 wants replaced by real congestion signal.
Genuinely unspent in substrate: `twcc.zig`, `bbr.zig`, `l4s.zig`, `raptorq.zig`,
`red_fec.zig`, `vad.zig`, `audio_mix.zig`, `plc.zig`, `dtx.zig`.

### F-32 — Consent-gated call recording
**Pitch:** recording is cryptographically impossible unless every participant's
client has released a key share, and the consent state is visible in-band.
**Why:** every platform's recording notice is a UI promise. Making it a key
release makes it a *property*. With E2EE media, the server genuinely cannot
produce a recording without cooperation — that is a differentiator no
mainstream platform can claim, and it is buildable because `media_epoch_key.zig`
already exists.
**Home:** `src/daemon/media_record.zig` (new), `src/substrate/media_epoch_key.zig`
**Owner:** onyx-server-media · **Cx:** L · **Deps:** E2EE media · **P1** · **★★★** · client: contract
**Fail-closed:** absent or withdrawn consent means no key share, means no
recording — never "record and hope the UI warned them."

### F-33 — Adaptive audio-only degradation
**Pitch:** under sustained loss, a receiver degrades video → low-rate audio →
DTX/comfort-noise rather than dropping the call.
**Why:** `dtx.zig:3-8`, `plc.zig`, `loss_monitor.zig`, and `cc_cubic.zig` are all
in substrate and unspent. The user story is "the call survived my train tunnel,"
which is the single most-felt quality difference in a voice product.
**Home:** `src/daemon/media_plane.zig`, `src/substrate/loss_monitor.zig`
**Owner:** onyx-server-media · **Cx:** M · **Deps:** S-16 · **P1** · **★★☆** · client: contract

### F-34 — Spatial audio rooms
**Pitch:** participants have positions; the SFU emits per-receiver spatial
metadata for client-side HRTF panning.
**Why:** the classic "who is talking" problem in a 12-person call disappears with
spatial separation, and it makes side conversations natural. The SFU already does
per-receiver work for simulcast (S-16), so the per-receiver hook exists.
**Home:** `src/daemon/media_room.zig`
**Owner:** onyx-server-media · **Cx:** M · **Deps:** S-16 · **P2** · **★★☆** · client: contract

### F-35 — Speaking-order queue ("raise hand" as protocol)
**Pitch:** a server-arbitrated speaking queue with an optional
only-the-floor-holder-is-unmuted mode.
**Why:** turns a call into a usable meeting or town hall for 50+ people. The
arbitration must be server-side or two clients race for the floor.
**Home:** `src/daemon/media_room.zig`, new MEDIA subcommand
**Owner:** onyx-server-media · **Cx:** S · **Deps:** — · **P1** · **★☆☆** · client: contract

### F-36 — Per-call quality forensics
**Pitch:** an end-of-call report per participant — loss, jitter, RTT
distribution, layer switches — retained briefly and readable by the operator.
**Why:** "the call was bad" is unactionable. `media_stats_agg.zig`,
`hdr_histogram.zig`, and `ddsketch.zig` exist; nothing renders them for a human.
**Home:** `src/daemon/media_forensics.zig` (new)
**Owner:** onyx-server-media · **Cx:** M · **Deps:** F-39 · **P1** · **★★☆** · client: gated

### F-37 — Live captions with translation hooks
**Pitch:** the existing caption ring gains a per-receiver language preference and
a pluggable translation sink.
**Why:** `transcript.zig:3-8` already fans out speaker-tagged captions pushed by
clients. Language routing is a small addition on top of a shipped feature, and it
makes a multilingual community actually work.
**Home:** `src/daemon/transcript.zig`
**Owner:** onyx-server-media · **Cx:** M · **Deps:** F-26 (sandbox for the sink) · **P2** · **★★☆** · client: contract

### F-38 — Media relay federation
**Pitch:** a call spanning two mesh nodes forwards between SFUs instead of
requiring every participant to reach one node.
**Why:** without this, media is effectively single-node and the mesh story stops
at text. This is the structural unlock for geographically distributed voice.
**Home:** `src/daemon/media_plane.zig`, `src/substrate/undertow/media.zig`
**Owner:** onyx-server-media · **Cx:** XL · **Deps:** S-16, S-17 · **P2** · **★★★** · client: none

---

## F — Observability & forensics

Existing today: **10** scalar counter/gauge families rendered from
`src/daemon/server_stats.zig:104-113`, served at `GET /metrics`
(`src/daemon/metrics_http.zig:4-21`), plus `status.json`, `qlog.zig`,
`trace.zig`, `tracing.zig`, `dlog.zig`, `audit_trail.zig`, `command_usage.zig`.

### F-39 — Deep metrics: histograms, not just counters
**Pitch:** latency histograms, per-subsystem gauges, and mesh/TLS/media coverage
on the `/metrics` endpoint.
**Why:** the current surface is ten scalars — connections, s2s links, bytes,
lines, quits, errors (`server_stats.zig:104-113`). There is no p99 anywhere, no
per-command latency, no TLS handshake timing, no mesh convergence lag, no media
jitter. Meanwhile `hdr_histogram.zig`, `ddsketch.zig`, and `tdigest.zig` sit
unused in substrate. This is the highest-leverage operational gap in the tree:
you cannot run a network you cannot see, and every other feature here gets
harder to validate without it.
**Home:** `src/daemon/server_stats.zig`, `metrics_http.zig`, `src/substrate/metrics.zig`
**Owner:** onyx-server-perf · **Cx:** M · **Deps:** — · **P0** · **★★☆** · client: none
**Invariant:** the hot path stays allocation-free and lock-free — histograms are
per-reactor and merged on the cold render path, exactly as the current counters
are (`server_stats.zig:5-9`).

### F-40 — Flight-recorder export on fault
**Pitch:** on a panic, a mesh partition, or an operator command, dump the
`qlog`/`trace` ring to a file with a bounded size.
**Why:** the flight recorder already keeps the last N events
(`server_stats.zig:11-12` references it) but there is no way to *get it out* at
the moment it matters. This is the cheapest debuggability win available —
small change, transforms every incident postmortem.
**Home:** `src/daemon/dlog.zig`, `src/substrate/qlog.zig`
**Owner:** onyx-server-perf · **Cx:** S · **Deps:** — · **P0** · **★★☆** · client: none

### F-41 — Per-command cost telemetry
**Pitch:** `command_usage.zig` gains CPU time and allocation attribution per
command, exposed via `STATS`.
**Why:** counting invocations does not tell an operator which command is eating
the node. Cost attribution is how you find the pathological `LISTX` before it
takes the node down — and it feeds the algorithmic-complexity DoS question
directly.
**Home:** `src/daemon/command_usage.zig`
**Owner:** onyx-server-perf · **Cx:** S · **Deps:** F-39 · **P1** · **★☆☆** · client: none

### F-42 — Distributed trace export (OpenTelemetry)
**Pitch:** a message's path across nodes carries a trace context and exports as
OTLP spans.
**Why:** `tracing.zig` and `trace.zig` exist locally. Cross-node causality is
otherwise unknowable — "why did this message take 4 seconds" has no answer on a
mesh without it.
**Home:** `src/substrate/tracing.zig`, `src/daemon/trace_export.zig` (new)
**Owner:** onyx-server-perf · **Cx:** L · **Deps:** F-24 (outbound HTTP pattern) · **P2** · **★★☆** · client: none

### F-43 — Audit log with tamper-evident chaining
**Pitch:** `audit_trail.zig` entries chain by hash so a deleted or altered entry
is detectable.
**Why:** an audit log an attacker can edit is not an audit log. `merkle.zig` and
`merkle_mountain_range.zig` already exist — an MMR gives append-only proofs
cheaply, and periodic root publication makes tampering externally detectable.
**Home:** `src/daemon/audit_trail.zig`, `src/substrate/merkle_mountain_range.zig`
**Owner:** zig-coder · **Cx:** M · **Deps:** — · **P1** · **★★☆** · client: none

### F-44 — Anomaly baselines with alerting
**Pitch:** the daemon learns its own normal (join rate, message rate, error rate)
and emits an Event Spine `security` event on deviation.
**Why:** static thresholds are wrong for every network but one. `ewma.zig`,
`ddsketch.zig`, and `count_min_sketch.zig` make a self-tuning baseline cheap, and
Event Spine already has the `security` category (`event_spine.zig:25`).
**Home:** `src/daemon/anomaly.zig` (new)
**Owner:** onyx-server-perf · **Cx:** M · **Deps:** F-39 · **P2** · **★★☆** · client: gated

### F-45 — Continuous capacity report
**Pitch:** a rolling projection — "at the current growth rate this node saturates
its connection class in 6 weeks."
**Why:** turns capacity planning from a fire drill into a scheduled task. Directly
serves the roadmap's S-20 and S-22 accept criteria, which both demand *measured*
rather than assumed bounds.
**Home:** `src/daemon/capacity.zig` (new)
**Owner:** onyx-server-perf · **Cx:** M · **Deps:** F-39 · **P2** · **★★☆** · client: none

---

## G — Self-host operator experience

This is the category with the highest ratio of user-visible value to
implementation cost, and it is the one an ambitious daemon most often neglects.

### F-46 — `onyx doctor` — preflight and live health audit
**Pitch:** one command that checks certificates, DNS, ports, file permissions,
clock skew, mesh reachability, disk headroom, and config coherence — and says
what to fix.
**Why:** `--check-config` answers "does this parse." It does not answer "will
this work," and the roadmap notes the real failure mode: *"a `ParseError` at boot
silently starts the default identity and needs a full restart to recover."* A
doctor command is the difference between self-hosting being plausible and being
an expert-only activity.
**Home:** `src/cli/doctor_cmd.zig` (new), `src/main.zig` dispatch
**Owner:** zig-coder · **Cx:** M · **Deps:** — · **P0** · **★★☆** · client: none
**Guard rail:** the new CLI verb uses **exact-match dispatch with a fail-closed
default** — an unrecognized arg must never fall through to "treat as config path"
(`src/main.zig:169-248`; `--version` once booted a stray daemon on the default port).

### F-47 — Config wizard and REHASH dry-run diff
**Pitch:** interactive generation of a minimal valid config, plus
`REHASH --dry-run` showing exactly what a reload would change.
**Why:** the reference config is 900 lines across ~40 sections
(`etc/onyx-server.reference.toml`). That is a wall for a new operator. And a live
REHASH is currently a leap of faith — a diff makes it a decision.
**Home:** `src/cli/config_wizard.zig` (new), `src/daemon/config_boot.zig`
**Owner:** onyx-server-config · **Cx:** S · **Deps:** — · **P0** · **★★☆** · client: none

### F-48 — Upgrade advisor
**Pitch:** before a USR2 hot-upgrade, the new binary reports capsule-version
compatibility against the running process and refuses on a mismatch.
**Why:** this is the S-14 failure mode caught *at the right moment*. The roadmap
states it precisely: *"a serialized-length change without a capsule version bump
and a legacy decode arm produces a netsplit on upgrade — a NEW-to-NEW round-trip
test passes while the real old-binary-to-new-binary path breaks."* An advisor
catches it in the 5 seconds before it becomes an outage.
**Home:** `src/daemon/helix/`, `src/cli/upgrade_advise.zig` (new)
**Owner:** onyx-server-helix-reviewer · **Cx:** M · **Deps:** S-14 · **P0** · **★★☆** · client: none

### F-49 — Guided mesh join
**Pitch:** an invite-token flow that walks a new node through key exchange,
policy agreement, and first sync with clear failure messages.
**Why:** mesh linking is the hardest thing to get right by hand and the highest
security stakes. A guided flow with explicit failure text is what makes
"run your own node and join us" a realistic sentence.
**Home:** `src/cli/mesh_join.zig` (new), `secured_s2s_link.zig`
**Owner:** onyx-server-mesh · **Cx:** M · **Deps:** F-11 · **P1** · **★★☆** · client: none
**Fail-closed:** an invite token that fails validation aborts the join — the
daemon never falls back to an unauthenticated link.

### F-50 — One-command backup verification
**Pitch:** restore the latest backup into a scratch instance and assert it boots
and reads back — on a schedule.
**Why:** `[backup]` writes timestamped snapshots
(`etc/onyx-server.reference.toml:849-853`). Nothing ever verifies they restore.
An unverified backup is a rumour.
**Home:** `src/cli/backup_verify.zig` (new)
**Owner:** onyx-server-store · **Cx:** M · **Deps:** — · **P1** · **★★☆** · client: none

### F-51 — Migration import from other daemons
**Pitch:** import accounts, channel registrations, and ban lists from
Atheme/Anope database exports.
**Why:** the single biggest adoption barrier for an existing network is losing
its account database. Import removes it. Strictly an offline CLI tool — no
production code path, no runtime risk.
**Home:** `src/cli/import_cmd.zig` (new)
**Owner:** zig-coder · **Cx:** L · **Deps:** — · **P2** · **★☆☆** · client: none

---

## H — IRCX & Event-Spine conversation primitives

The IRCX plane (`PROP`, `ACCESS`, `SACCESS`, `DATA`, `EVENT`, `MODEX`, `LISTX`,
`WHISPER`) is the daemon's most distinctive protocol surface and the natural home
for primitives that IRC has never had.

### F-52 — Scheduled & deferred delivery
**Pitch:** `SCHEDULE <target> <when> :<message>` — send later, recurring via cron,
cancellable, surviving USR2.
**Why:** `src/substrate/cron.zig:3-7` is a complete 5-field cron parser with
`nextAfter()` — and **nothing in the tree consumes it**. The scheduler is the
missing 20%. Unlocks reminders, recurring announcements, timed moderation (F-03),
and scheduled events, all from one mechanism.
**Home:** `src/daemon/scheduler.zig` (new), a Helix capsule for durability
**Owner:** onyx-server-ircx · **Cx:** M · **Deps:** — · **P0** · **★★☆** · client: contract
**Guard rail:** the fire-check tick is periodic shared-state maintenance —
**reactor-0-gated**, single owner, no exceptions.

### F-53 — Threads as first-class objects
**Pitch:** a thread gets a stable, mesh-portable identity — subscribable,
listable, with its own membership and history window.
**Why:** `draft/reply` exists as a *tag* today, which makes a thread an emergent
property of message metadata rather than a thing. The roadmap already names the
hard part in cross-cutting row **X-6**: *"a thread identity that does not survive
a node change is worse than no threading."* That is exactly why this needs an
architected key (`snowflake.zig`/`ulid.zig` are both in substrate), not a client
convention.
**Home:** `src/daemon/thread.zig` (new), `src/proto/lotus.zig` history rings
**Owner:** onyx-server-ircx · **Cx:** L · **Deps:** S-03 · **P0** · **★★☆** · client: contract

### F-54 — Channel events with RSVP
**Pitch:** a scheduled event object with attendance state, reminders, and an
auto-created call room.
**Why:** community coordination currently lives in a pinned topic. `poll.zig`
proves the per-channel bounded-object pattern; an event is that plus a time and
a media room. Composes F-52 for reminders and `media_room.zig` for the room.
**Home:** `src/daemon/event_object.zig` (new)
**Owner:** onyx-server-ircx · **Cx:** M · **Deps:** F-52 · **P1** · **★★☆** · client: contract

### F-55 — Persistent channel canvas
**Pitch:** a small collaboratively edited document per channel, converged with
the CRDT text type already in substrate.
**Why:** `crdt_text.zig`, `egwalker.zig`, and `eg_walker.zig` are all present —
a real collaborative-text CRDT is sitting unused. A shared channel document
(rules, agenda, running notes) is exactly the shape that fits, and it is a thing
no IRC daemon offers.
**Home:** `src/daemon/canvas.zig` (new), `src/substrate/crdt_text.zig`
**Owner:** onyx-server-ircx · **Cx:** L · **Deps:** mesh CRDT · **P2** · **★★★** · client: contract

### F-56 — Message bookmarks and saved items
**Pitch:** per-account saved messages with tags, synced across devices, listable.
**Why:** `PINS` is per-channel and operator-curated. A personal bookmark is the
missing per-user axis, and it is the feature people notice missing within a day
of using a modern chat client.
**Home:** `src/daemon/bookmark.zig` (new)
**Owner:** onyx-server-ircx · **Cx:** S · **Deps:** — · **P1** · **★☆☆** · client: contract

### F-57 — Conversation digests
**Pitch:** a periodic summary of channel activity — top threads, unread counts,
mention roll-up — delivered on a schedule.
**Why:** the answer to "I was away for a week and #dev has 4,000 messages."
Summarization is statistical (`topk.zig`, `count_min_sketch.zig`,
`minhash.zig` — all present), not an LLM dependency. Composes F-52 for delivery.
**Home:** `src/daemon/digest.zig` (new)
**Owner:** onyx-server-ircx · **Cx:** M · **Deps:** F-52, F-53 · **P2** · **★★☆** · client: contract

### F-58 — Channel forum mode
**Pitch:** a channel mode where every top-level message is a thread root, with a
listable index.
**Why:** a small mode flag on top of F-53 that changes the interaction model
entirely — support channels and Q&A stop being a scrollback race. A free letter
is available in `chanmode_ext` (`src/proto/chanmode_ext.zig:52-71`).
**Home:** `src/proto/chanmode_ext.zig`, `src/daemon/thread.zig`
**Owner:** onyx-server-ircx · **Cx:** M · **Deps:** F-53 · **P2** · **★★☆** · client: contract

---

## I — Privacy & E2EE

Existing: `e2ee_group_mesh_authority.zig`, `e2ee_group_outbox.zig`,
`e2ee_group_replay_guard.zig`, `e2ee_group_dst.zig`, `key_transparency.zig`,
`key_transparency_store.zig`, and the `onyx/e2ee` capability. Roadmap S-12 and
S-13 cover activation; these are the features beyond it.

### F-59 — Per-channel retention policy engine
**Pitch:** a channel declares "forget after N days," and the daemon enforces
deletion across history, search index, and mesh replicas.
**Why:** retention is currently implicit and unbounded. The hard part is that
deletion must reach `search_index.zig`, `lotus.zig` rings, the mesh replicas, and
the backups — a CRDT tombstone problem, not a `DELETE`. Doing it properly is
both a privacy feature and a storage-growth answer for S-20.
**Home:** `src/daemon/retention.zig` (new)
**Owner:** onyx-server-store · **Cx:** M · **Deps:** S-06 · **P0** · **★★☆** · client: gated
**Invariant:** a retention deletion is a replicated tombstone with origin and
HLC, not a local erase — otherwise a partition heals the data back.

### F-60 — Sealed rooms: metadata-minimal channels
**Pitch:** a channel where the daemon stores no membership list, no topic, and no
plaintext — routing by capability token rather than by identity.
**Why:** E2EE hides content; metadata is what actually deanonymizes people. A
room whose membership the server *cannot enumerate* is a fundamentally stronger
claim than "we encrypt messages," and no mainstream platform offers it. Genuinely
hard — routing without an identity list means capability-token routing — but it
is the most differentiated idea in this catalog.
**Home:** `src/daemon/sealed_room.zig` (new)
**Owner:** stack-architect (design first) → zig-coder · **Cx:** XL · **Deps:** S-12 ·
**P2** · **★★★** · client: contract
**Marked PLAUSIBLE:** the routing model needs a full design pass before anyone
estimates it. Do not schedule this from this catalog entry alone.

### F-61 — Key transparency with client-verifiable proofs
**Pitch:** the key directory publishes inclusion and consistency proofs a client
can check independently.
**Why:** S-13 gets device entries replicating. Verifiability is what makes the
directory *trustworthy* rather than merely *available* — without it a malicious
node can hand one client a different key set. `sparse_merkle.zig` and
`merkle_mountain_range.zig` are both already in substrate.
**Home:** `src/daemon/key_transparency.zig`
**Owner:** onyx-server-crypto-reviewer (design) → zig-coder · **Cx:** L · **Deps:** S-13 ·
**P1** · **★★★** · client: contract

### F-62 — Metadata minimization mode
**Pitch:** a node-level mode that drops or coarsens connection metadata — no IP
logging, timestamp bucketing, padded message sizes.
**Why:** operators in hostile jurisdictions need "we cannot comply because we do
not have it." This must be a *node* posture with visible consequences (some
anti-abuse features degrade), not a per-user toggle that pretends to be free.
**Home:** `src/daemon/privacy_mode.zig` (new)
**Owner:** onyx-server-config · **Cx:** M · **Deps:** — · **P2** · **★★☆** · client: gated
**Honest trade-off:** this directly weakens F-15, F-18, and `ip_reputation.zig`.
The mode must say so at boot, not discover it in production.

### F-63 — Forward-secure history re-keying
**Pitch:** periodic epoch rotation so a compromised current key does not decrypt
last month's history.
**Why:** the group E2EE design already forward-secures on member removal (S-12
accept criteria). Time-based rotation extends that to the compromise case, which
is the more common one.
**Home:** `src/daemon/e2ee_group_mesh_authority.zig`
**Owner:** onyx-server-crypto-reviewer · **Cx:** L · **Deps:** S-12 · **P2** · **★★☆** · client: contract

---

## J — Performance & scale

### F-64 — Read-replica history nodes
**Pitch:** a node that serves history and search from a replicated read-only
index without carrying live sessions.
**Why:** history search (S-06) is the most expensive read on the daemon and it
competes with the hot path for the same reactors. Splitting it is the standard
answer and the mesh already has the replication primitives.
**Home:** `src/daemon/search_index.zig`, `src/substrate/undertow/`
**Owner:** onyx-server-perf · **Cx:** L · **Deps:** S-06, F-14 · **P2** · **★★☆** · client: none

### F-65 — Tiered history storage
**Pitch:** hot history in memory, warm on disk, cold in compressed archives, with
transparent promotion.
**Why:** unbounded history is the storage-growth failure mode S-20 names.
`range_coder.zig` and the WAL are already there; tiering is the policy layer that
makes retention (F-59) and growth planning (F-45) tractable.
**Home:** `src/daemon/store.zig`, `src/substrate/wal.zig`
**Owner:** onyx-server-store · **Cx:** L · **Deps:** S-20 · **P2** · **★★☆** · client: none

### F-66 — Adaptive shard rebalancing
**Pitch:** connections migrate between reactor shards when load skews.
**Why:** `consistent_hash.zig` and `rendezvous_hash.zig` exist; a hot shard
currently stays hot until its clients leave. Rebalancing is the difference
between average and worst-case latency under real traffic.
**Home:** `src/daemon/shard.zig`, `reactor_fabric.zig`
**Owner:** onyx-server-reactor · **Cx:** L · **Deps:** — · **P2** · **★★☆** · client: none
**Risk:** migration must preserve `ClientId` shard-pinning invariants. This needs
a DST campaign (S-15) before it is trusted — cross-shard ordering is exactly the
bug class DST exists for.

### F-67 — Connection hibernation
**Pitch:** an idle connection's state compacts to a minimal footprint and rehydrates on activity.
**Why:** most connections are idle most of the time. Hibernation is the direct
lever on memory-per-connection, which is what actually caps a node's connection
count. Composes with the bouncer/session capsules Helix already carries.
**Home:** `src/daemon/client.zig`, `src/daemon/helix/`
**Owner:** onyx-server-perf · **Cx:** L · **Deps:** — · **P2** · **★★☆** · client: none

### F-68 — Edge acceleration nodes
**Pitch:** lightweight nodes that terminate TLS and relay to a core node,
reducing handshake RTT for distant users.
**Why:** TLS handshake latency dominates connect time for geographically distant
users. Edge termination is the standard fix and composes with F-14 observer nodes
and F-11 selective federation.
**Home:** new deployment topology over `secured_s2s_link.zig`
**Owner:** onyx-server-mesh · **Cx:** XL · **Deps:** F-11, F-14 · **P2** · **★★☆** · client: none
**Security note:** an edge node terminating TLS **sees plaintext**. It must be a
full-trust peer, or the design must keep E2EE content sealed through it. State
which, explicitly, before building.

---

## Wire contract discipline

Anything marked `client: contract` above is a **cross-repo change** and inherits
the roadmap's ordering rule (see [`ROADMAP-2026-Q4.md` § Cross-cutting](../ROADMAP-2026-Q4.md#cross-cutting-server--client-wire-contracts)):

- **Capability and token additions ship server-first** — a client that sends a
  token the daemon does not understand is a broken session.
- **Client reinterpretations of existing wire data ship client-first.**
- Every contract feature must land in
  `docs/reference/protocol/onyx-client-contract.v2.json` before its client half
  is marked done, and must be **byte-identical when the feature is off**.
- Every contract feature owes an **old-client story** and a **mid-USR2-peer
  story**. A feature that only works when both ends are new is not shippable on a
  live mesh.

Features here that add a channel mode letter (F-16, F-58) must claim from the
genuinely free set. **Two files own letters, and a design that reads only one
will collide:**

- `src/daemon/chanmode.zig` — core modes: `A b C e g i I k l m M n N O o q Q s S t T v W Y`
- `src/proto/chanmode_ext.zig:52-71` — IRCX MODEX extension modes:
  `a d D E f F h i m n p r s t u U V w x z`

Unclaimed at HEAD: `B c G H j J K L P R X Z y`. Verify against both files at the
time of design — this list is a snapshot, not a reservation.

---

## Standing guard rails for anything built from this catalog

These are not advice; they are the failure classes this daemon has already paid for.

| Guard rail | Applies to | Rule |
| --- | --- | --- |
| **Multi-reactor timer fan-out** | F-03, F-15, F-18, F-24, F-44, F-52, F-59 | `onTimerTick` fires on **every** reactor. Any new periodic shared-state task names a single owning reactor (`src/daemon/server.zig:5163,5259`) or is provably reactor-local. |
| **Liveness ≠ value convergence** | F-08, F-15, F-20, F-59 | A "still here / last seen" refresh is **never** gated on a newer HLC. Only CRDT *value* writes take the LWW path. |
| **Fail-closed crypto** | F-08, F-11, F-32, F-49, F-60, F-61 | No path may limp on a keyless/unsigned peer. Fail-closed is the default for every new security branch. |
| **Mesh identity = shortId** | F-08, F-11, F-13, F-14, F-38 | Never key on nick or UID for an S2S-routed decision. |
| **ARGV exact-match dispatch** | F-46, F-47, F-48, F-50, F-51 | A new CLI verb must not fall through to "treat as config path" (`src/main.zig:169-248`). |
| **Typed tokens, never markup** | F-27, F-28, F-37, F-55, F-57 | Renderable content is parsed to typed tokens. No HTML reaches the client pipeline. |
| **DST before trust** | F-08, F-18, F-38, F-59, F-66 | Anything touching mesh convergence, upgrade, or cross-shard ordering owes a seeded campaign (roadmap S-15). |

---

## Risks in this catalog itself

| Severity | Risk | Mitigation |
| --- | --- | --- |
| **HIGH** | **Scope displacement.** The roadmap has 30 unfinished items including three P0s (S-01, S-02, S-12). Building F-features instead of finishing S-features leaves the daemon broad and shallow. | Treat this catalog as *later*, with the exception of the Top 5 — each of which directly serves an existing S-item (F-39→S-09/S-22, F-10→S-05, F-48→S-14, F-08→S-29). |
| **HIGH** | **Contract sprawl.** 29 of the 68 features are `client: contract` (10 `gated`, 29 daemon-internal). Each contract item is a two-repo negotiation and a v2-contract entry. | Batch contract changes into at most two waves per release. Never ship a contract change without its client item scheduled. |
| **MEDIUM** | **Substrate mirage.** "The primitive already exists" (`cron.zig`, `simulcast_select.zig`, `crdt_text.zig`) understates integration cost — the primitive is usually 20% of the work. | Every S/M estimate here assumes integration, not just wiring. Re-estimate at design time. |
| **MEDIUM** | **Novelty ≠ demand.** F-55, F-60, and F-38 are the most differentiated and the least validated by user request. | Gate ★★★/XL items behind a stated user need before design, not after. |
| **LOW** | **Estimate confidence.** Complexity here is architect judgment from module survey, not from implementation spikes. | Treat `L`/`XL` as "needs a design doc before an estimate," not as a schedule. |

---

## Verdict

**GO — as a catalog.** No item here is scheduled by this document and nothing in
it authorizes code. The two HIGH risks are both about *sequencing*, not about the
features being wrong, and both have named mitigations.

**Recommended intake for 0.7:** F-39, F-15, F-52, F-08, F-24 — five features,
one per subsystem owner, four of which reinforce an existing roadmap item rather
than competing with it.

**Not buildable from this document alone:** F-60 (sealed rooms) is marked
**PLAUSIBLE** — the capability-token routing model has not been designed, and the
XL estimate is a guess until it has been. F-38 (media relay federation) and F-68
(edge nodes) similarly need a design pass before anyone commits to them.

**What was not checked:** client-side feasibility for every `contract` item (the
onyx repo was not surveyed for this document), and no item here has an
implementation spike behind its complexity estimate.
