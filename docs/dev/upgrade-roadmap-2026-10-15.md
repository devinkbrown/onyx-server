# Onyx Server upgrade roadmap (2026-10-15)

Working tree on `portability/openbsd` at `c5d14934`, plus uncommitted Armor and IRCX edits. Nothing in this document is a deploy, a push, or a commit. Live dual-node units stay on the image recorded in `docs/ops/onyx-server-paths.md`.

Swarm result, 2026-10-15:

- S-1 / IX-C / U-1 landed in `src/proto/help_db.zig`. Standalone tests: 8 passed under `qemu-x86_64 -cpu max` after the untargeted ELF SIGILL'd on BMI2. No daemon `zig build`.
- IX-B / U-2 landed. Native `test.real` for `IRCX CREATE reply carries the new channel oid`: 74 passed, 0 failed. An oid of `0` is omitted.
- M-1 finished with no confirmed ceiling. Four read-only Undertow lenses found no owned file that refuses a 65th peer, node, or membership. No undertow diff. Fix phase did not run.

Current source and tests win. `docs/ROADMAP-GAPS-2026-09.md` is a frozen audit and is often stale. `docs/dev/tls-roadmap.md` cuts stay closed. This file is the execution map for services, IRCX, mesh scale, and the user-facing command surface.

## 0. Rules for every lane

- Pure Zig 0.17. No C. No `std.heap.GeneralPurposeAllocator`. Tests use `std.testing.allocator`.
- `zig fmt` on touched Zig files.
- One writer per file. `src/daemon/server.zig` has one writer: `onyx-server-integrator`.
- Do not revert uncommitted work listed in section 1.
- Do not edit `build.zig` to rename optimize tags.
- Do not signal `onyx-server.service`, do not write `/home/kain/onyx-server-run` or `/home/trev/onyx-server-run`, and do not push.
- Compiler on this host: `/tmp/zig-ivy/bin/zig` under `python3 /tmp/zig-ptrace.py`, target `x86_64-linux-musl`, cpu `x86_64`. Unset `LD_LIBRARY_PATH` in the parent. Give every compile its own `ZIG_LOCAL_CACHE_DIR`. `/tmp/zig-ptrace.py` runs those project binaries on this kernel and qemu-wraps only `maker` and `configurer`. `createTestServer` (heap) is the server test constructor. `Server.init` returned by value has overflowed the stack in `GAP-P0c remote LISTX`.

## 1. Already in the working tree

Do not reimplement these. Do not revert them while landing a later slice.

| Slice | Behavior | Files |
| --- | --- | --- |
| Armor name constraints | A wildcard dNSName is the set of one-label expansions. An excluded subtree rejects the name if any expansion falls inside. A permitted subtree accepts it only if every expansion falls inside. The accepted DNS name is checked against every presented CA and the trust anchor. TLS 1.3 and TLS 1.2 clients both do this. | `src/crypto/x509_verify.zig`, `src/crypto/tls_client.zig`, `src/crypto/tls12_client.zig` |
| IRCX LAG | Stored `LAG` of `1` or `2` seconds delays every member, including voice, channel operators, and network operators. `SLOWMODE` exemptions are unchanged. A sender who is subject to both waits the longer gap. They share `slowmode_last`. A stored value other than `0`, `1`, or `2` adds no delay. The setter rejects anything else. | `src/daemon/server.zig`, `src/proto/ircx_prop_store.zig` |
| LISTX query limit | `LISTX <filter> <limit>`. `0` or a missing limit uses the server cap of 1024. A larger request is clamped to 1024. `816` is emitted only when another match remains. A non-numeric second token stays `InvalidParameter`. | `src/proto/listx.zig`, `src/daemon/server.zig` |
| ONJOIN / ONPART | ONJOIN is a `PRIVMSG` and ONPART is a `NOTICE`. The channel name is the sender. Only the joining or parting client receives it. The stored characters `\` and `n` start another line. A stored control byte drops the whole value. | `src/daemon/server.zig` |

Armor tests on the musl binary: 121 passed, 3 skipped, 0 failed, 0 leaked. IRCX LAG and LISTX: the filtered native run passed both new tests. ONJOIN: `IRCX ONJOIN is a channel PRIVMSG and ONPART is a channel NOTICE` passed (74 passed, 0 failed, 0 leaked in that filtered binary). Full `zig build test` has not been run.

Residual, deliberately untouched: `src/cli/verify_cmd.zig` still does not apply name constraints. The CLI comment overclaims CA bits, path length, and name constraints.

## 2. Cuts that stay closed

These are product decisions. A swarm must not reopen them.

| Cut | What stays |
| --- | --- |
| Armor TLS roadmap | No ECH+HRR implementation, no ChaCha-only HPKE change, no extra key shares, no AES-CCM, no zlib-only cert compression, no `armor enc`, no live `-connect`, no caller-supplied CRL/CT turned on by default, no PQ signing (verify-only ML-DSA/SLH-DSA stays), no DTLS on the TLS listener, no kTLS txrx, no live OCSP fetch, no `defer_taskrun`, no MESSAGE_V2 activation. |
| IRCX divergences | No `TACCESS` / `BTPROP` / `OPFORCE` / `SVSJOIN`. No Comic Chat `DATA` avatar. `WALLOPS` stays folded into `EVENT BROADCAST`. MODEX numerics stay 826/827. LISTX 812 layout stays `<channel> <members> <created_ms> <topic_ms> :<topic>`. `C`/`T` ages stay milliseconds. `EventCategory.parse("CHANNEL")` stays null. `MAXCODEPAGE=0` and `MAXLANGUAGE=0` stay. |
| Services shape | No NickServ-style pseudo-clients. Account and channel services are real server commands. No second AKICK store. The top-level AKICK command was removed because `CHANNEL AKICK` is the persistent join gate. |
| Mesh wire | No silent legacy fallthrough when MESSAGE_V2 is required. MeshPass stays inside encrypted M1. Nick collision on the mesh renames the loser to the UID. Local nick clash stays numeric 433. |
| Security defaults | `RESETPASS` request replies stay identical whether or not the account exists. TOTP enroll stays TLS-only. NOTICE still never emits error replies. |

## 3. Track S — services

Onyx Server services are the account, channel, memo, and oper commands in `src/daemon/modules/accounts.zig`, `services_ext.zig`, and `feature_misc.zig`. Handlers live in `server.zig`. Leaf stores live in `svc_*.zig` and `services.zig`.

| ID | Work | Owner file | State |
| --- | --- | --- | --- |
| S-1 | `HELP` topics for the account and service verbs a person actually types: `REGISTER`, `VERIFY`, `IDENTIFY`, `TOTP`, `RECOVERYCODES`, `LOGOUT`, `DROP`, `SETPASS`, `RESETPASS`, `SUCCESSOR`, `ACCOUNTINFO`, `ACCOUNTSET`, `GHOST`, `RECOVER`, `RELEASE`, `CHANNEL`, `SESSION`, `MEMO`, `AUTOJOIN`, `WELCOME`, `CERTADD`, `WEBAUTHN`, `E2EEKEY`. Syntax comes from `docs/reference/commands/`. | `src/proto/help_db.zig` | Landed |
| S-2 | Keep password-reset anti-enumeration and TOTP transport checks as they are. A help line may describe them. A handler change may not weaken them. | none | Closed |
| S-3 | `CHANNEL` subcommand text in `HELP CHANNEL` (register, access, akick, drop) matching the live handler. No new subcommand. | `src/proto/help_db.zig` | Landed inside S-1 |
| S-4 | After S-1, read `handleRegister`, `handleIdentify`, `handleChannel`, and `handleMemo` for a reply that contradicts the command page. Patch only a confirmed contradiction. | `src/daemon/server.zig` | Next integrator turn, after S-1 and IX-B |
| S-5 | Memo, welcome-pack, and autojoin delivery stay one-time or list-shaped as already implemented. Do not add a second welcome path beside `welcome_pack.zig` and channel `ONJOIN`. | none | Closed |

Accept S-1 when `lookup` returns a topic for every name in the table, each topic has a syntax line plus one behavior line, existing JOIN/MODE/PRIVMSG/OPER/CHATHISTORY bytes stay exact, and unknown topics still return numeric 524.

## 4. Track IX — IRCX

Draft source: `docs/reference/ircx/ircx-draft-pfenning-04.md` and the IETF text it extracts. Live verbs are the `ircx` module.

| ID | Work | Owner file | State |
| --- | --- | --- | --- |
| IX-A | LAG, LISTX limit, ONJOIN, ONPART. | already edited | Done in the working tree |
| IX-B | After a successful `CREATE` of a channel that did not exist, send the creating client one server message: `CREATE <channel> <oid>`. `<oid>` is `0` plus 8 lowercase hex digits, the same spelling as `PROP` `OID` (`world.channelOid`, formatted `0{x:0>8}`). Do not broadcast it. Do not send it for an ordinary `JOIN` that happens to create a channel. Do not send it when `CREATE` fails with 926. A missing oid, or a stored oid of `0`, skips the line. | `src/daemon/server.zig`, CREATE replies bullet in `docs/reference/commands/channels.md` | Landed |
| IX-C | `HELP` topics for `IRCX`, `ISIRCX`, `LISTX`, `MODEX`, `PROP`, `ACCESS`, `SACCESS`, `AUTH`, `EVENT`, `DATA`, `REQUEST`, `REPLY`, `WHISPER`, `CREATE`. | `src/proto/help_db.zig` | Landed with S-1 |
| IX-D | OID as a channel-name shortcut. A parameter that is `0` plus exactly 8 hex digits resolves to the channel with that oid. Any other token stays a literal name. Missing oid is `ERR_NOSUCHCHANNEL`. Apply it on the channel-parameter commands (`JOIN`, `PART`, `NAMES`, `MODE`, `TOPIC`, `KICK`, `INVITE`, `KNOCK`, `PRIVMSG`, `NOTICE`, `WHO`, `PROP`, `ACCESS`, `MODEX`). This is one integrator slice. It does not run beside IX-B. | `src/daemon/server.zig` | Next, after IX-B is tested |
| IX-E | `EVENT` `CHANGE` still allows only `MEDIA` for a non-oper, while `ADD`/`DELETE` allow `CHANNEL`, `MEMBER`, and `MEDIA`. `docs/reference/ircx/m_ircx_event.md` says MEDIA only. Do not widen `CHANGE` and do not narrow `ADD`/`DELETE` until one contract is chosen in a review. | none | Held |
| IX-F | `CLIENT` is a 255-character property with the same set/read rules as `TOPIC`. It is not a join filter. Do not add one. | none | Closed |

Accept IX-B when a heap `createTestServer` test shows the creator receives `CREATE #name 0........` equal to `channelOid`, a later joiner does not receive a new `CREATE`, a second `CREATE` of the same name is 926, and a plain `JOIN` of a new channel does not emit `CREATE`.

## 5. Track M — mesh

Undertow is the mesh. The live pair is eshmaki.me and ircx.us. This track does not deploy.

| ID | Work | Owner files | State |
| --- | --- | --- | --- |
| M-1 | Find fixed peer, node, or membership ceilings that refuse, truncate, or overwrite the 65th item. Grow real ones from the allocator. A test must admit 65. Partition-detector work replaces a dense matrix with a sparse edge list. Leave nick, channel, account, and key lengths alone. Leave `resolveIncomingNick` and sticky trust alone. | `src/substrate/undertow/route_table.zig`, `s2s_peer.zig`, `gossip_round.zig`, `gossip_views.zig`, `membership_view.zig`, `membership_burst.zig`, `server_registry.zig`, `mesh.zig`, `mesh_topology.zig`, `partition_detector.zig`, `peer_link.zig` | Audited. No confirmed ceiling. No diff. |
| M-2 | Empty audit is a successful result. Do not invent a ceiling to have a diff. | same | Done. Four lenses, zero confirmed findings. |
| M-3 | Presence, replay, and Helix adopt stay on their existing fail-closed paths. No MESSAGE_V2 flag flip. | none | Closed for this swarm |
| M-4 | After M-1, if the patch touches route fanout, run the focused mesh test in the worktree and record the pass count before copying any hunk back. | undertow files only | Skipped. M-1 produced no patch. |

Accept M-1 when every confirmed ceiling either grows past 64 with a test, or the written audit says no owned file refuses the 65th peer.

## 6. Track U — user experience

This repository is the daemon. User experience here means the bytes a client shows: help, creation identity, join and part notices, list truncation, and account commands. The Onyx client tree is out of scope.

| ID | What the person sees | State |
| --- | --- | --- |
| U-1 | `HELP` with no argument still resolves to the `HELP` topic. That topic gains a line naming the IRCX, account, and channel topics. `HELP LISTX`, `HELP REGISTER`, and `HELP MEMO` return 704/705/706 instead of 524. | Landed |
| U-2 | Creating a room with `CREATE` tells the client the room oid in the draft `CREATE` message, so later UI can store it. Joining an existing room does not pretend to create it. | Landed |
| U-3 | Joining shows the channel's on-join text as a channel-sourced `PRIVMSG`. Parting shows on-part text as a channel-sourced `NOTICE`. Other people in the room do not see those lines. | Done |
| U-4 | A room list can ask for a short page (`LISTX <filter> <limit>`) and can tell truncation (`816`) from a short natural result. | Done |
| U-5 | A slow room (`LAG` 1 or 2) slows every speaker. Voice and operators still skip `SLOWMODE` only. The refusal text says `lag` when lag is the reason and `slowmode` when slowmode is the reason. | Done |
| U-6 | `COMMANDS` already lists registry summaries. `HELP` is the long form. Do not fork a third help store. | Closed |
| U-7 | Command-page drift found by S-4 or IX-D is fixed in the same change as the handler. Historical evidence under `docs/audit/evidence/` is not edited. | Later |

Accept U-1 and U-2 with the tests named on S-1 and IX-B. A client screenshot is not a daemon gate.

## 7. Swarm running against this document

Lanes launched together. File sets do not overlap. Each compile uses its own local Zig cache.

| Lane | Agent | Writes | Result |
| --- | --- | --- | --- |
| Help | `zig-coder-leaf` | `src/proto/help_db.zig` | Landed. 8 tests passed. |
| CREATE oid | `onyx-server-integrator` | `src/daemon/server.zig`, the CREATE replies bullet in `docs/reference/commands/channels.md` | Landed. Native filtered run 74 passed, 0 failed. |
| Mesh ceilings | workflow `mesh-scale-audit` | owned undertow files only if a ceiling was confirmed | Complete with zero findings. No patch. |

`src/crypto/tls_client.zig`, `tls12_client.zig`, and `x509_verify.zig` have no owner in this swarm.

## 8. Gates

| When | Command |
| --- | --- |
| Help iteration | `zig test src/proto/help_db.zig` with a private cache. Do not `zig build` the daemon while IX-B is compiling. |
| CREATE iteration | `zig build test-mod-verbose -Dtest-filter='IRCX CREATE reply' -Dtarget=x86_64-linux-musl -Dcpu=x86_64`, then run `test.real` natively. |
| Mesh iteration | the workflow's filtered `test-mod-verbose` inside its worktree. |
| Ship, later | `scripts/select-gates.py` on the changed paths, then full `zig build test` with a pass count. `server.zig` selects `test-server` and `test-services`. IRCX paths select `test-ircx`. Those are the ship gate, not the iteration command. |

## 9. After this swarm

1. Mesh audit returned no patch. Do not invent a ceiling.
2. Run IX-D (oid shortcut) as the next single `server.zig` slice.
3. Pick one `EVENT CHANGE` contract in review, then implement that one.
4. S-4: one pass over register, identify, channel, and memo replies against the command pages.
5. Fresh reviewer on IX-B and on any mesh ceiling that changed fanout. Writers do not grade their own work.
6. Full Debug gate, then ReleaseSafe on the mesh or server slice that shipped. Still no deploy until that evidence exists and the operator asks.
