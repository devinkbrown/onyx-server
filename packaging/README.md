# Onyx Server — self-host quickstart & reproducible releases

Onyx Server is a single, static, **zero-external-dependency** binary named
**`onyx-server`**. There is no database server to run, no OpenSSL to patch, no
runtime to install — it ships its own TLS 1.3 stack, its own mesh, and its own
services. This directory holds everything to run it and to prove the binary you
run is the one from source.

## Honest release path (what you actually get)

| Path | What it produces | When to use it |
|---|---|---|
| `zig build` | `zig-out/bin/onyx-server` (debug / local) | Development, smoke tests |
| `zig build package --prefix <dir>` | staged `bin/onyx-server` + reference config + systemd unit | Production install from a built tree |
| `packaging/release.sh` | `dist/onyx-server-<version>-x86_64-linux-musl` + `SHA256SUMS` + SBOM + provenance | Reproducible attested static binary |

The first verified prebuilt is the public
[`v0.5.6` GitHub Release](https://github.com/devinkbrown/onyx-server/releases/tag/v0.5.6).
It includes the static musl binary, quickstart config, checksum manifest,
CycloneDX SBOM, and provenance statement. The manifest is reproducible and was
download-smoked through IRC and WebSocket before publication. It is **not yet
cryptographically signed**, so verify the checksum and provenance and use the
source rebuild path below when your threat model requires independent trust.
There is still no published registry image; Docker remains build-from-source.

The daemon binary is always **`onyx-server`**. The release script only prefixes a
version and target on the *artifact filename*
(`onyx-server-0.x.y-x86_64-linux-musl`); install/copy it as `onyx-server` (the
Dockerfile does this). Older historical names in a local `dist/` are historical
leftovers — ignore them; `release.sh` emits `onyx-server-*` only.

Validate a config **without** booting:

```sh
./zig-out/bin/onyx-server --check-config packaging/onyx-server.quickstart.toml
# or, once installed:
onyx-server --check-config /etc/onyx-server/onyx-server.toml
```

`--check-config` is a real flag (`src/main.zig`): parse + preflight, print
`config OK` / `config ERROR`, exit. No listeners, no mesh dial. The packaged
systemd unit runs it as `ExecStartPre` so a bad config fails the start instead of
risking a silent fall-through to the built-in DEFAULT identity.

## Quickstart (native)

```sh
# 1. Download the published static binary, quickstart, and checksum manifest.
release=https://github.com/devinkbrown/onyx-server/releases/download/v0.5.6
curl -fLO "$release/onyx-server-0.5.6-x86_64-linux-musl"
curl -fLO "$release/onyx-server.quickstart.toml"
curl -fLO "$release/SHA256SUMS"

# 2. Verify the downloaded binary, make it executable, preflight, and run.
grep ' onyx-server-0.5.6-x86_64-linux-musl$' SHA256SUMS | sha256sum -c -
chmod +x onyx-server-0.5.6-x86_64-linux-musl
./onyx-server-0.5.6-x86_64-linux-musl --check-config onyx-server.quickstart.toml
./onyx-server-0.5.6-x86_64-linux-musl onyx-server.quickstart.toml
```

Once the process is running, the daemon itself is up quickly (typically well
under a second to bind listeners on a warm host). That is **boot** time, not
clone/build/DNS/ACME time.

- **`ws://localhost:8080`** — the browser WebSocket endpoint for the Onyx web client.
- **`irc://localhost:6667`** — plaintext IRC for any IRC client.

The node's **sovereign identity key** (`onyx-server-node.key`) and the account store
(`accounts.db`) are generated in the working directory on first run — nothing to
configure for local evaluation. For production, see [Production TLS card](#production-tls-card).

## Quickstart (Docker)

```sh
packaging/release.sh                                   # build the verified static binary → dist/
docker build -f packaging/Dockerfile -t onyx-server:latest .
docker run -p 6667:6667 -p 8080:8080 -v onyx-server:/data onyx-server:latest
```

`/data` holds the node key + account store — the named volume persists them. The
image copies the release artifact to `/usr/local/bin/onyx-server` (binary name
fixed; version stays in the `dist/` filename only).

## Production TLS card

Local quickstart is plaintext on purpose. A **public** node needs DNS, TLS, and
`wss`. Checklist (single node; mesh is a later rung — see `docs/guide/mesh.md`):

| Step | What to do |
|---|---|
| 1. DNS | Point `A`/`AAAA` for your hostname at the host. |
| 2. Ports | Open client TLS (`6697/tcp` by default). For ACME HTTP-01, arrange port 80 reachability (daemon `challenge_port` + reverse proxy is the usual pattern). |
| 3. Paths | Put cert/key PEMs on durable paths (e.g. `/etc/onyx-server/tls/{cert,key}.pem`), mode `0640` / `0600` on the key. |
| 4. Config | Enable `[tls]` with `cert_path`/`key_path`/`dns_name`. Enable `[acme]` when using the built-in client. Set `[listen] ws_plain = false`. Set a real `[network].server_name`. |
| 5. Preflight | `onyx-server --check-config /path/to.toml` must print `config OK`. |
| 6. Run under systemd | Prefer the unit in `etc/systemd/onyx-server.service` (`ExecStartPre=… --check-config …`). Day-2 upgrade is `systemctl reload` (Helix), not a blind restart. |

Minimal production sketch (fill in host, email, and paths):

```toml
[network]
name = "Onyx"
server_name = "irc.example.net"

[listen]
host = "::"
irc = 6667          # optional plaintext; many operators fire-wall this off
ws = 8080
ws_plain = false    # browsers need wss for a public client

[tls]
enabled = true
port = 6697
cert_path = "/etc/onyx-server/tls/cert.pem"
key_path = "/etc/onyx-server/tls/key.pem"
dns_name = "irc.example.net"

[sts]
enabled = true
duration = 2592000
port = 6697

[acme]
enabled = true
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
domain = "irc.example.net"
contact = "mailto:admin@example.net"
# challenge_port = 14402   # loopback HTTP-01; reverse-proxy 80 → this port
```

Self-signed bootstrap (enabled `[tls]` with no cert/key paths) is fine for **local**
eval only. Do not point a public web client origin at a self-signed leaf and call
it production. Full field reference: `docs/guide/tls.md`, `docs/reference/config.md`,
`etc/onyx-server.reference.toml`.

## systemd (production UX)

The source unit is `etc/systemd/onyx-server.service` (also staged by
`zig build package` under `lib/systemd/system/onyx-server.service`):

```ini
ExecStartPre=/usr/local/bin/onyx-server --check-config /etc/onyx-server/onyx-server.toml
ExecStart=/usr/local/bin/onyx-server /etc/onyx-server/onyx-server.toml
ExecReload=/bin/kill -USR2 $MAINPID
```

- **Cold start / restart** runs `ExecStartPre` first — bad TOML or preflight failure
  keeps the previous unit state from being replaced by a DEFAULT-identity daemon.
- **`systemctl reload onyx-server`** is the normal upgrade path (Helix / SIGUSR2;
  sessions kept). Reload does **not** re-run `ExecStartPre`; always
  `--check-config` yourself before reloading after a config change.
- Install steps and hardening notes: `docs/RUNBOOK.md`.

## Connecting the web client

Onyx (the first-party client) picks its server at build time via `VITE_IRC_WS`:

```sh
cd /path/to/onyx
VITE_IRC_WS=ws://localhost:8080 pnpm build   # dist/ now points at your node
# serve dist/ with any static file server (or a hosted Onyx build)
```

Any standard IRC client works too — point it at `localhost:6667` (or `6697` with TLS).

## Reproducible releases (trust, not faith)

Because the build is hermetic (pure Zig, no C interop) and static
(`x86_64-linux-musl`), a `ReleaseFast` build **at a fixed commit is bit-for-bit
reproducible**. You never have to trust the release machine.

```sh
packaging/release.sh          # → dist/{onyx-server-<ver>-x86_64-linux-musl, SHA256SUMS, onyx-server.cdx.json, onyx-server.provenance.json}
packaging/verify-release.sh   # rebuild from source with a clean cache; must match SHA256SUMS
```

`verify-release.sh` exits non-zero if the rebuild is not byte-identical — so a
tampered or differently-sourced binary is caught mechanically. Both scripts
refuse to run on a dirty tree (which would embed a non-reproducible `-dirty`
version).

**The whole release is reproducible, not just the binary** — for a given
`(commit, Zig toolchain)`. The SBOM carries no timestamps and the provenance pins
its build times *and* its source `ref` to the commit (not the wall clock or the
local branch), so re-running `release.sh` on the same commit with the same `zig`
reproduces every file — binary, SBOM, provenance, and `SHA256SUMS` — bit-for-bit.
(Reproducible builds always require a fixed toolchain; Onyx Server's is pinned in
`build.zig.zon`'s `minimum_zig_version`.) Only `git`, `zig`, and `sha256sum` are
required; `cosign` and `jq` are optional and degrade to a note when absent.

`verify-release.sh` rebuilds and proves the **binary** is byte-identical, binds
the shipped binary to the manifest, and re-checks the SBOM/provenance integrity;
the SBOM and provenance are reproducible *by construction* (no wall-clock inputs),
so re-running `release.sh` on the same commit regenerates them identically.

### `SHA256SUMS` — one manifest, all artifacts

`SHA256SUMS` lists the binary (first line), the SBOM, and the provenance. A
single cosign signature over it therefore anchors the integrity of the entire
release. `verify-release.sh` rebuilds the binary and, if the SBOM/provenance are
present, re-checks them against the manifest to catch post-publish tampering.

### Signing (cosign)

`release.sh` cosign-signs `SHA256SUMS` when a signer is configured
(`COSIGN_KEY=<key>` for a key file, or keyless `COSIGN_EXPERIMENTAL=1` under CI
OIDC), producing `SHA256SUMS.sig`. `verify-release.sh` checks it when
`COSIGN_PUBKEY` is set. If `cosign` is not installed or no signer is configured,
signing is **skipped with a note** — the release still builds and verifies.

### SBOM (CycloneDX)

`onyx-server.cdx.json` is a CycloneDX 1.5 SBOM — and it fits on one screen, because the
component graph is a single binary with **zero external dependencies**. The only
thing recorded is the Zig toolchain that produced it, as a build *tool* (not a
runtime component). That is the whole security pitch: the software bill of
materials is effectively one line.

### Provenance (SLSA v1 shape)

`onyx-server.provenance.json` is an in-toto Statement carrying an SLSA-provenance-v1
predicate. It records **what** was built (the artifact + its sha256), **from
what** (repo, ref, full commit), **how** (the exact `zig build …` command +
toolchain version), and **by whom** (the `release.sh` builder id). Because it is
listed in `SHA256SUMS`, the cosign signature authenticates it — the local-builder
equivalent of SLSA L2. Running the identical steps on a hosted runner (e.g. the
`slsa-github-generator` GitHub Action with an isolated builder identity) is what
elevates this to *true* SLSA L2/L3; the field shapes here are drop-in compatible
with that upgrade.

## A10 — First public GitHub Release (completed 2026-07-20)

The human-authorized release is public at
[`v0.5.6`](https://github.com/devinkbrown/onyx-server/releases/tag/v0.5.6).
The executed gate was:

1. Clean tree on the release commit: `git status` empty (else `release.sh` refuses).
2. `packaging/release.sh` → `dist/onyx-server-<ver>-x86_64-linux-musl` + `SHA256SUMS` + SBOM + provenance.
3. `packaging/verify-release.sh` on that `dist/` — binary bit-identical rebuild.
4. Optional: cosign when `COSIGN_KEY` / keyless CI is ready.
5. Create **GitHub Release** on `devinkbrown/onyx-server` attaching:
   - the musl binary
   - `SHA256SUMS` (+ `.sig` if present)
   - SBOM + provenance JSON
6. Smoke: download on a clean machine → `./onyx-server --check-config …` → chat on 8080.
7. Only then update landing self-host CTAs from "build from source" to "download the release".

All seven steps passed. The release remains deliberately labeled unsigned until
a cosign identity is configured; checksum, SBOM, provenance, reproducibility,
and download smoke are current evidence, not a substitute for a signature.
