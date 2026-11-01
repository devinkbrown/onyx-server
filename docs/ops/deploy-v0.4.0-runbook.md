# Onyx Server v0.4.0 — Production Deploy Runbook (both mesh nodes)

> **Superseded / historical — preserved as evidence.** This document is a point-in-time record and does not describe the current source or fleet. Current truth: [docs hub](../README.md) and [production paths](../ops/onyx-server-paths.md). Do not execute it as a current procedure.


> **Naming note (2026-07):** This runbook records the **v0.4.0** deploy as executed.
> The product is now **Onyx Server** (repo `/home/kain/onyx-server`, binary `onyx-server`).
> Banner text `Onyx Server 0.4.0+…` and `journalctl -u onyx` below are **historical literals**
> from that release/unit name — do not rewrite them into a modern checklist.


Run top-to-bottom. This is a **hard restart** (`systemctl restart`, NOT USR2) of both
live nodes, authorized by the operator. One static musl artifact serves both nodes
(both are `x86_64-linux`, statically linked).

| | Node A (home) | Node B (peer) |
|---|---|---|
| Host | `eshmaki.me` (LOCAL) | `ircx.us` (`ssh trev@ircx.us`) |
| Run dir | `/home/kain/onyx-server-run/` | `/home/trev/onyx-run/` |
| Config | `onyx-server.local.toml` | `onyx-server.ircxus.toml` |
| Improved config | `/tmp/claude-1000/config-improved/eshmaki.improved.toml` | `/tmp/claude-1000/config-improved/ircxus.improved.toml` |
| systemd unit | `onyx-server` (system unit, `User=kain`) | `onyx-server` (system unit) |
| node id / shards | id=1, num_shards=4 | id=2, num_shards=1 |
| Ports | irc 6667 · tls 6697 · ws 8080 · s2s 6900 · metrics 9130(lo) | same, minus metrics scope |

**Rollout order: Node B (ircx.us) FIRST, then Node A (eshmaki).** Rationale: upgrade the
remote/secondary peer first, confirm it is healthy, and finish on the operator-present
home node with a known-good peer already up.

> ⚠️ **Mixed-version mesh gap (expected, not a failure).** Both improved configs set
> `require_signed_frames = true`, which the **new** binary enforces and the **old** binary
> ignores. While one node is new and the other is still old, the S2S link will **not**
> re-form. The mesh only reconverges once **both** nodes run 0.4.0. Do the real mesh-reattach
> verification in **§4**, after both restarts — not between them.

> ⚠️ **NEVER run the bare binary** (`./onyx-server` with no subcommand) — it strays a `:6680`
> listener. Only `--check-config <file>` (validates and exits) and `systemctl` are allowed
> to launch it.

---

## §1 — Pre-flight (on Node A / build host = eshmaki local)

All commands from `/home/kain/onyx-server`.

**1.1 Commit the pending 0.4.0 work — the tree is currently dirty.**
The working tree has uncommitted TLS 1.3 hardening (5 files, ~682 insertions) plus an
untracked research doc. The build stamps the version **`-dirty`** if the tree is not clean,
which fails the banner check in §3. Review and commit first:

```bash
cd /home/kain/onyx-server  # (repo path was /home/kain/onyx-server at the time of this deploy)
git status --porcelain           # see what is pending
git diff --stat HEAD             # 5 crypto/tls files expected
# review the diff, then:
git add -A
git commit -m "harden(tls): TLS1.2 EMS + TLS1.3 HRR/key_share/0-RTT/ECH, argon2id cloak KDF, warden live-ward, cross-shard perf"
git status --porcelain           # MUST now be EMPTY
```

**1.2 Gate green — full test suite.**
```bash
zig build test 2>&1 | tail -20   # must finish with no failures
```

**1.3 Push / merge to github.**
```bash
git log --oneline github/main..HEAD    # confirm the commits to publish
git push github main
git rev-parse --short HEAD              # record the deploy hash → <HASH>
```

**1.4 Build the musl ReleaseFast artifact.** (NOT `zig build release` = Debug.)
```bash
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux-musl
file zig-out/bin/onyx-server     # MUST say: ELF 64-bit ... x86-64 ... statically linked
```

**1.5 SHA256 the artifact — record it.**
```bash
sha256sum zig-out/bin/onyx-server | tee /tmp/onyx-0.4.0.sha256
# record the hex → <SHA256>. This is verified on-node after transfer.
```

**1.6 `--check-config` BOTH improved configs against the freshly built binary.**
```bash
zig-out/bin/onyx-server --check-config /tmp/claude-1000/config-improved/eshmaki.improved.toml
zig-out/bin/onyx-server --check-config /tmp/claude-1000/config-improved/ircxus.improved.toml
# BOTH must print OK. If either ERRORs, STOP — do not deploy.
```

**Pre-flight gate:** clean tree ✓ · tests green ✓ · pushed ✓ · static binary ✓ · sha recorded ✓ · both configs OK ✓.

---

## §2 — Backup / rollback prep (each node)

Timestamp: `TS=$(date +%Y%m%d-%H%M%S)`.

**2.1 Node B (ircx.us) — back up current binary + config.**
```bash
ssh trev@ircx.us 'cd /home/trev/onyx-run && TS=$(date +%Y%m%d-%H%M%S) && \
  cp -a onyx onyx_server.bak-$TS-pre-0.4.0 && \
  cp -a onyx-server.ircxus.toml onyx-server.ircxus.toml.bak-$TS && \
  ls -la onyx_server.bak-$TS-pre-0.4.0 onyx-server.ircxus.toml.bak-$TS'
```

**2.2 Node A (eshmaki, local) — back up current binary + config.**
```bash
# Historical run dir (repo was /home/kain/onyx-server at the time of this deploy).
cd /home/kain/onyx-server-run && TS=$(date +%Y%m%d-%H%M%S) && \
  cp -a onyx onyx_server.bak-$TS-pre-0.4.0 && \
  cp -a onyx-server.local.toml onyx-server.local.toml.bak-$TS && \
  ls -la onyx_server.bak-$TS-pre-0.4.0 onyx-server.local.toml.bak-$TS
```

Rollback is then one `mv` + restart (see §5). Note the exact backup filenames printed.

---

## §3 — Node-by-node rollout

### §3-B  Node B = ircx.us (FIRST)

**3B.1 Stage the new binary atomically (transfer → verify sha → atomic rename).**
```bash
scp /home/kain/onyx-server/zig-out/bin/onyx-server trev@ircx.us:/home/trev/onyx-run/onyx_server.new
ssh trev@ircx.us 'sha256sum /home/trev/onyx-run/onyx_server.new'   # MUST equal <SHA256> from §1.5
```

**3B.2 `--check-config` the STAGED binary against the improved config (before swap).**
```bash
scp /tmp/claude-1000/config-improved/ircxus.improved.toml trev@ircx.us:/home/trev/onyx-run/onyx-server.ircxus.toml.new
ssh trev@ircx.us '/home/trev/onyx-run/onyx_server.new --check-config /home/trev/onyx-run/onyx-server.ircxus.toml.new'
# MUST print OK. If ERROR: STOP, do not swap, do not restart.
```

**3B.3 Atomic swap of binary + config into place.**
```bash
ssh trev@ircx.us 'cd /home/trev/onyx-run && \
  mv onyx_server.new onyx && \
  mv onyx-server.ircxus.toml.new onyx-server.ircxus.toml && \
  chmod +x onyx'
```

**3B.4 Hard restart.**
```bash
ssh trev@ircx.us 'sudo systemctl restart onyx'
```
> If the unit is not privileged for `trev`, use the operator's usual restart path for
> node B. It is a system unit (`/etc/systemd/system/onyx-server.service`).

**3B.5 Post-restart health checks (Node B).**
```bash
# a) service active, not restart-looping
ssh trev@ircx.us 'systemctl is-active onyx && systemctl status onyx --no-pager | head -12'

# b) version banner shows 0.4.0+<HASH> with NO -dirty suffix
ssh trev@ircx.us 'journalctl -u onyx -n 40 --no-pager | grep -A1 "Onyx Server 0.4.0"'

# c) listeners up (irc 6667, tls 6697, ws 8080, s2s 6900)
ssh trev@ircx.us "ss -ltnp | grep -E ':(6667|6697|8080|6900)\b'"

# d) TLS handshake on :6697 completes with a valid cert
ssh trev@ircx.us "echo | openssl s_client -connect ircx.us:6697 -servername ircx.us 2>/dev/null | openssl x509 -noout -subject -dates"
```
Expected: `active`; banner `Onyx Server 0.4.0+<HASH>` (no `-dirty`); all four ports LISTEN;
TLS subject + valid notBefore/notAfter.

> At this point the mesh link to A will likely be **down** (A is still old, B now enforces
> signed frames). **This is expected** — do not roll back for it. Proceed to Node A.

### §3-A  Node A = eshmaki (SECOND, local)

**3A.1 Stage the new binary atomically (local same-fs rename).**
```bash
cp -a /home/kain/onyx-server/zig-out/bin/onyx-server /home/kain/onyx-server-run/onyx_server.new
sha256sum /home/kain/onyx-server-run/onyx_server.new    # MUST equal <SHA256> from §1.5
```

**3A.2 `--check-config` the staged binary against the improved config.**
```bash
cp /tmp/claude-1000/config-improved/eshmaki.improved.toml /home/kain/onyx-server-run/onyx-server.local.toml.new
/home/kain/onyx-server-run/onyx_server.new --check-config /home/kain/onyx-server-run/onyx-server.local.toml.new
# MUST print OK. If ERROR: STOP, do not swap.
```

**3A.3 Atomic swap.**
```bash
# Historical run dir (repo was /home/kain/onyx-server at the time of this deploy).
cd /home/kain/onyx-server-run && \
  mv onyx_server.new onyx && \
  mv onyx-server.local.toml.new onyx-server.local.toml && \
  chmod +x onyx
```

**3A.4 Hard restart.**
```bash
sudo systemctl restart onyx
```

**3A.5 Post-restart health checks (Node A).**
```bash
systemctl is-active onyx && systemctl status onyx --no-pager | head -12
journalctl -u onyx -n 40 --no-pager | grep -A1 "Onyx Server 0.4.0"
ss -ltnp | grep -E ':(6667|6697|8080|6900|9130)\b'
echo | openssl s_client -connect eshmaki.me:6697 -servername eshmaki.me 2>/dev/null | openssl x509 -noout -subject -dates
```
Expected: `active`; banner `Onyx Server 0.4.0+<HASH>` (no `-dirty`); ports 6667/6697/8080/6900
LISTEN (+9130 on loopback); TLS handshake OK.

---

## §4 — Mesh verification across both nodes (no split-brain)

Both nodes now run 0.4.0, so the signed-frame S2S link should re-form within
~`handshake_timeout_ms`/heartbeat (seconds to ~30s). Give it up to ~60s, then verify.

**4.1 Peers see each other.** As an oper on each node, issue `MESH` (peer/link health),
`LINKS`, and `MAP`:
```
# On a client connected to eshmaki.me (oper): 
MESH        -> ircx.us listed, link state up/linked
LINKS       -> lists ircx.us
MAP         -> both eshmaki.me and ircx.us present

# On a client connected to ircx.us (oper):
MESH        -> eshmaki.me listed, link state up/linked
LINKS / MAP -> symmetric (both nodes present)
```

**4.2 Split-brain check — both sides agree on one network.**
```
# Global counts must MATCH across nodes (same mesh view, not two islands):
LUSERS      on eshmaki  vs  LUSERS on ircx.us   -> global user/server totals agree
LIST        -> a channel with members on both nodes shows the global member count
```
Convergence proof: from a client on eshmaki, `JOIN #deploytest`; from a client on ircx.us,
`NAMES #deploytest` — the eshmaki member must appear (PROP/membership crossed the mesh).

**4.3 Log sanity on BOTH nodes.**
```bash
journalctl -u onyx -n 80 --no-pager | grep -Ei 'resync|anti.?entropy|split|collision|zombie|panic'
ssh trev@ircx.us "journalctl -u onyx -n 80 --no-pager | grep -Ei 'resync|anti.?entropy|split|collision|zombie|panic'"
```
Expected: a one-time RESYNC/anti-entropy convergence after relink; **no** persistent
`split`, no collision storm, no `panic`. A single burst of collision renames right after
relink that then quiesces is normal; a continuous storm is not.

**Mesh gate:** each node sees the other in `MESH`/`LINKS`/`MAP` ✓ · LUSERS totals agree ✓ ·
cross-node JOIN visible ✓ · logs converged, no panic/split ✓.

---

## §5 — Abort / rollback

**Abort criteria (any of):**
- `--check-config` ERROR on a node (§3B.2 / §3A.2) — never swap/restart.
- `systemctl is-active` ≠ `active`, or the unit restart-loops (`status` shows repeated starts).
- Banner missing, wrong version, or shows `-dirty`.
- A configured listener (6667/6697/8080/6900) fails to bind.
- TLS handshake on :6697 fails.
- After **both** nodes are 0.4.0, the mesh does not converge within a few minutes
  (persistent split-brain: `MESH`/`LINKS` never shows the peer, LUSERS totals disagree).

Roll back **the affected node** (do B before touching A if B fails; if A fails after B is
already live, roll A back — B on 0.4.0 alone is fine and will simply wait for A).

**5.1 Rollback Node B (ircx.us).**
```bash
ssh trev@ircx.us 'cd /home/trev/onyx-run && \
  mv onyx_server.bak-<TS>-pre-0.4.0 onyx && \
  cp -a onyx-server.ircxus.toml.bak-<TS> onyx-server.ircxus.toml && \
  sudo systemctl restart onyx && systemctl is-active onyx'
```

**5.2 Rollback Node A (eshmaki).**
```bash
# Historical run dir (repo was /home/kain/onyx-server at the time of this deploy).
cd /home/kain/onyx-server-run && \
  mv onyx_server.bak-<TS>-pre-0.4.0 onyx && \
  cp -a onyx-server.local.toml.bak-<TS> onyx-server.local.toml && \
  sudo systemctl restart onyx && systemctl is-active onyx
```
Substitute the exact backup filenames recorded in §2. After rollback, re-verify §4 with
both nodes back on the old binary.

---

## §6 — Post-deploy checklist

- [ ] Both nodes report `Onyx Server 0.4.0+<HASH>` (no `-dirty`) in the banner / `VERSION`.
- [ ] Mesh converged: each node sees the other in `MESH`/`LINKS`/`MAP`; LUSERS agree; no split-brain.
- [ ] **Expected one-time cloak reshuffle.** The argon2id + auth-split anon-epoch cloak
      change means every user's cloaked host is recomputed on first boot of 0.4.0. This is
      expected, not a bug.
- [ ] **Re-add host/subnet WARD bans.** Because cloaked hosts changed, pre-upgrade
      **host/subnet-mask** WARDs no longer match and must be re-added after this deploy.
      (Account-based and raw IP/CIDR wards are unaffected — only cloaked-host/subnet wards.)
      Re-issue the needed `WARD` entries once both nodes are confirmed up.
- [ ] Improved configs are now live (`onyx-server.local.toml`, `onyx-server.ircxus.toml`); backups
      retained at the `*.bak-<TS>` paths from §2.
- [ ] `github/main` is at `<HASH>` (pushed in §1.3).
- [ ] Clean up staged temp files if any remain (`onyx_server.new`, `*.toml.new`) — none should
      after a successful swap.
- [ ] Update the deploy note / memory: `onyx-0.4.0+<HASH>` deployed to both nodes via
      hard `systemctl restart`, mesh reconverged, cloak reshuffle done, host/subnet WARDs re-added.
