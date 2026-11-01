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
| `zig build package --prefix <dir>` | staged daemon + reference config + target-specific deployment assets | Production install from a built tree |
| `packaging/release.sh` | `dist/onyx-server-<version>-x86_64-linux-musl` + `SHA256SUMS` + SBOM + provenance | Reproducible attested static binary |

Current source version is **0.8.0** (`build.zig.zon`). The first verified
prebuilt on GitHub remains the public
[`v0.5.6` Release](https://github.com/devinkbrown/onyx-server/releases/tag/v0.5.6).
The verified fleet is still `0.7.0+ae78d490`. Build locally with
`packaging/release.sh` for **0.8.0**. The full test suite has not been
re-run green on this manifest.
It includes the static musl binary, quickstart config, checksum manifest,
CycloneDX SBOM, and provenance statement. The manifest is reproducible and was
download-smoked through IRC and WebSocket before publication. It is **not yet
cryptographically signed**, so verify the checksum and provenance and use the
source rebuild path below when your threat model requires independent trust.
There is still no published registry image; Docker remains build-from-source.

The live fleet is tracked separately from the public artifact channel: on
2026-09-06 both production nodes were verified on `0.7.0+ae78d490` under
`onyx-server.service` (artifact SHA-256
`0f110e833bc96bd6540ad7df0a620af869526cf8b4dbc3fd4650aa8ada8ddf1c`). The
checkout can advance beyond that deployed image; consult
[`docs/ops/onyx-server-paths.md`](../docs/ops/onyx-server-paths.md) for the
current runtime evidence before replacing a binary.

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

**Build current (0.8.0):**

```sh
packaging/release.sh
./dist/onyx-server-0.8.0-x86_64-linux-musl --check-config packaging/onyx-server.quickstart.toml
./dist/onyx-server-0.8.0-x86_64-linux-musl packaging/onyx-server.quickstart.toml
```

**Or download the latest published GitHub Release (v0.5.6):**

```sh
release=https://github.com/devinkbrown/onyx-server/releases/download/v0.5.6
curl -fLO "$release/onyx-server-0.5.6-x86_64-linux-musl"
curl -fLO "$release/onyx-server.quickstart.toml"
curl -fLO "$release/SHA256SUMS"
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

## Quickstart (Windows)

Use `onyx-server.windows.quickstart.toml` on Windows. Its account store lives in
`accounts-private`, which must be created with the daemon's native
`--init-private-dir` command before config preflight. The template binds IRC and
WebSocket to loopback only. See the [Windows guide](../docs/guide/windows.md)
for the PowerShell setup and native acceptance check.
The Windows `zig build package -Dtarget=x86_64-windows` bundle stages the
ReleaseFast executable in `bin/` and the reference and quickstart configs in
`etc/onyx-server/`.

## Quickstart (Docker)

```sh
packaging/release.sh                                   # build the verified static binary → dist/
docker build -f packaging/Dockerfile -t onyx-server:latest .
docker run --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  -p 6667:6667 -p 8080:8080 -v onyx-server:/data onyx-server:latest
```

The process runs as UID/GID `10001:10001`. `/data` is mode `0700` and contains
the initial `0600` quickstart config, generated node key, and account store;
the named volume persists them. The node key is generated **beside the config**,
so the default config is `/data/onyx-server.toml`. An existing volume is never
overwritten with a new config. A bind-mounted `/data` must already contain the
reviewed config and be writable by UID/GID 10001. Before upgrading an older
volume, provision `/data/onyx-server.toml` explicitly; older images kept that
config under `/etc`. Preserve any existing node key and account store.

The root filesystem can be requested read-only while `/data` remains writable.
Production config and secret files can be mounted read-only inside `/data`,
with permissions allowing UID 10001 to read them. Keep the parent directory
writable for identity generation, or provision its existing identity privately.
Point every enabled mutable feature (ACME, logs, databases, media caches) to
the deliberate writable volume. Logs use inherited stdout/stderr by default;
bound retention using your container runtime's logging settings.

The image copies the static musl release artifact to
`/usr/local/bin/onyx-server`; Alpine supplies the runtime filesystem and account
metadata. No shell wrapper or OpenRC daemon is launched in the container.
Arguments after the image name replace the default config argument, allowing
preflight with `--check-config /data/onyx-server.toml`. Run that against a
provisioned volume before starting the daemon. Container read-only-root and
capability restrictions still require an actual container-engine acceptance
run; the [native Alpine smoke](../docs/guide/alpine.md) establishes a separate
host-runtime recovery boundary.

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

Release tooling supports `x86_64-linux-musl` (default) and
`aarch64-linux-musl`, with explicit `baseline` CPU and ReleaseFast optimization.
Use a separate output directory for each target:

```sh
packaging/release.sh dist/x86_64 x86_64-linux-musl
packaging/verify-release.sh dist/x86_64/SHA256SUMS x86_64-linux-musl
packaging/release.sh dist/aarch64 aarch64-linux-musl
packaging/verify-release.sh dist/aarch64/SHA256SUMS aarch64-linux-musl
```

Both scripts require a clean checkout and refuse dirty or unreadable Git state.
They require Bash, Git, Zig, Python 3, `sha256sum` and standard shell utilities.
Each output includes checksummed `onyx-server.build.json`, binding the source
commit, target, CPU, build flags, compiler version and compiler binary digest.
The verifier selects the exact target artifact and compares these inputs before
an independent clean-cache rebuild. Older manifests without this metadata are
not supported by the current verifier; retain their matching historical verifier.

A successful rebuild demonstrates byte equality for the recorded binary and
inputs. Cross-compilation does not establish native execution on that CPU or
Alpine runtime acceptance. The compiler executable hash does not cover its whole
standard-library distribution. The minimum Zig version in `build.zig.zon` is
not a complete toolchain pin. Record and retain the complete tested toolchain.

Metadata uses commit-derived dates and source identity. Verify repeat-build byte
equality before claiming a particular release is reproducible; pure Zig and
static linking alone do not prove it. The verifier also checks the integrity of
present SBOM/provenance files. Optional signatures require separate signer
verification; a configured signer that cannot run causes release generation to
fail. No release or native architecture proof follows from script unit tests.

### `SHA256SUMS` — one manifest, all artifacts

`SHA256SUMS` lists the binary, build metadata, SBOM, and provenance. A
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
