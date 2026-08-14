# Onyx Server 0.5.8 session roster convergence release

Deployed 2026-08-14 to `eshmaki.me` and `ircx.us`.

## Release identity

- Source commit: `31b6be1` (`fix: converge resumed session identities`)
- Runtime version: `Onyx Server 0.5.8+31b6be1`
- ReleaseFast SHA-256: `77e55d699de3e35000ee36e74073eb39cd279f4027a418782426be2682f1368c`
- Client companion commit: `f977e74b` (`fix: reconcile resumed session rosters`)
- Client release: `20260814-113411-f977e74b`

## Correctness boundary

This release closes the resumed-session roster split between canonical account
nicks, temporary 433 aliases, and receiver-derived mesh UIDs. Exact-token aliases
collapse to one logical member; genuine different-token collisions remain
distinct. Stale mesh membership now emits ordered client-visible removal before
route deletion, and retryable resume failures do not release temporary-nick
autojoin through a follow-up `SESSION TOKEN` request.

The companion client scopes delayed work to the socket generation, discards
unfinished NAMES bursts across reconnects, keeps authenticated alias equivalence
for the attachment lifetime, and fails closed when reconstructing per-spelling
channel modes after an equivalent identity departs.

## Release gates

- Client: 507 test files, 6,558 tests; typecheck; focused ESLint; production build.
- Server full: 8,345 passed, 4 expected skips.
- Server ReleaseSafe session lane: 698/698.
- Focused server/session/mesh lanes and fresh adversarial reviews passed.
- Both production TOMLs passed `--check-config` with the staged release binary.

## Deployment evidence

Helix upgraded one node at a time without changing either systemd MainPID or
incrementing `NRestarts`.

- `eshmaki.me`: re-attached 6 client connections and restored 5 sessions; one
  secured mesh link preserved.
- `ircx.us`: re-attached 3 client connections and restored 3 sessions; one
  secured mesh link preserved.
- Both `/proc/<MainPID>/exe` hashes equal the ReleaseFast hash above.
- Dual-node metrics: `links_active=1`, `peers_up=1`, `partitioned=0`,
  `tcp_active=1` on both nodes.
- `EXPECT_VER=31b6be1 tools/era2_acceptance_smoke.sh`: PASS. The first invocation
  used the script's historical default revision and correctly failed version
  comparison before the explicit release revision was supplied.
- Guest cross-node smoke: registration/JOIN plus exact A-to-B and B-to-A
  `PRIVMSG` delivery passed.
- The live client `index.html` and `sw.js` hashes match `/home/kain/onyx/out`.

## Rollback artifacts

The pre-release binary SHA-256 on both nodes was
`19f08e0aca5ee29187d4fefe4a138dd7998f469116a81d144c71b1196caea4bd`.

- Local: `/home/kain/onyx-server-run/onyx-server.prev-20260814-31b6be1`
- Peer: `/home/trev/onyx-server-run/onyx-server.prev-20260814-31b6be1`

Rollback must respect the Helix compatibility and MESSAGE_V2 activation
boundaries in `docs/RUNBOOK.md`.
