# Retiring mesh roster authority repair

Frozen `src/daemon/server.zig` SHA-256:
`b060677639a5f6f63c83dada6ebe7254f7fbb6a83a31e7d61b942cebabe2c187`.
Baseline: `b815280a0cc44db9e7f8a02dc7b86ae3cc665a0d343103ae360c27d05eccb708`.
Writer owns only server.zig; no leaf, deployment, VM, push or commit changes.

## Cause and bounded change

A healthy duplicate loser remains established while its final wire/SendQ drains.
Its receive admission is stopped, so its roster may have older membership,
account and home facts than the survivor, including a frozen higher HLC. Cross-
connection roster selectors still read that loser and either selected its higher
claim or returned its first matching membership/account. A valid signed
MESSAGE_V2 was then rejected permanently; E2EEGROUP was rejected. WHOIS,
channel privileges, NAMES/LIST, metadata and topology views had the same stale
connection selection hazard.

Twenty-two Server methods now skip occupied connections marked closing or
s2s_dedup before consuming their roster/view. Twenty-three scans changed;
`sendNamesWithProjection` guards both capacity estimation and row projection.
There is no allocation, transaction, replay or wire change in these guards.
All other production methods and existing tests remain byte-identical to b815:
`roster-production-delta-proof.txt` proves exact reversal of just the guards plus
removal of the new fixture block reproduces the entire baseline source.
Exact methods are in `roster-guard-functions.txt`; delta in
`retiring-roster-final.diff`.

## Adjacent consumer audit

Enumerated Server calls to bestNickClaim, findRemoteMember, channelMembers,
channelNames, channelTopic, channelModeFlags, remoteNickCount, nodeName,
nodeDescription and collectTopology.

- Home routing, trusted account lookup, direct-origin identity and origin server
  names now choose active connections. Their relaySenderHome,
  trustedRemoteAccountForNick, MESSAGE_V2 and E2EEGROUP callers inherit this cut.
- Remote channel membership/status, oper-prefix authority, WHOIS identity and
  WHOIS channels, global member count, remote-only channels, topic/secret flags,
  NAMES rows, peer names, LINKS/topology and active mesh count use the same cut.
- Per-link relayWanted is reached only through already guarded outbound route
  selectors. remoteWhoisFromLink and linkChannelHasMember are reached only from
  guarded cross-connection selectors. emitRemoteNick is an inbound identity
  transition on the admitted link, not a cross-connection authority search.
- netsplitOnPeerDrop and sealSecuredLink intentionally read the exact lifecycle
  link roster. Prune/route cleanup, dedicated duplicate-drain work, FD custody,
  checkpoint state and physical socket statistics remain unchanged.
- Reusable-session residence functions consult the signed retained SessionReplica
  Store, not a frozen per-connection roster; those durable facts remain valid.

## Regression and count oracle

Ten heap-based buffered secured-link tests place a retained full-SendQ loser
before its survivor, authenticate both with the same full peer key and diverge
higher-HLC stale homes/accounts/membership/status/topic/flags. They exercise
Server selectors and real signed MESSAGE_V2/E2EEGROUP admission/delivery,
accepted then duplicate with exactly one client payload. Loser ciphertext,
outer counter and held tail are checked unchanged. These are buffered link
fixtures; the focused gate also includes the pre-existing real socket mesh and
sequential Helix tests. All new cases permit Linux and OpenBSD with no platform
skip on either.

The active-user count assertion preserves the existing counter semantics:
RouteTable's nick index contains the two handshake server-name keys plus Sender
and Ghost; all four keys and the one local Target are explicitly checked. The
correct active value is 5; including the retained loser returns 10. This repair
does not redesign that inherited route-index counter.

Corrected causal RED source:
`c9153dc569990862a0b9d8228be0363adb27ef8af10b1e8742d0d3989478727e`.
Restoring original 22 selector bodies while keeping the corrected fixture gives
71/81 tests passed, all ten regressions failed, including expected5/found10,
MESSAGE_V2 permanent and E2EEGROUP rejected.
Command: `zig build test-mod -Dtest-filter='same-IP mesh dial retiring roster'`.
Log: `roster-corrected-final-causal-before-debug.log`.
After restoring the guards, that exact ten-case Debug command exits 0.
Log: `roster-corrected-final-after-debug.log` (default quiet success).
Final focused mode counts/check results will be appended after completion.
Parent owns fresh independent ALL-authority review and broad/full/native gates.
