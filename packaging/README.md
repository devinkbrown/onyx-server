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

Current source version is **0.10.0**, declared by `build.zig.zon`. Build a
candidate from a clean checkout and verify its exact source/compiler inputs
with the release scripts. The accepted production artifact, service-kit revision,
full Debug/ReleaseSafe results and native multi-client acceptance are recorded
in the [current release record](../docs/audit/release-0.10.0-2026-11-06.md).
The [production paths](../docs/ops/onyx-server-paths.md) page owns current node,
supervisor, version and executable-hash facts. A new local build is a separate
candidate until its gates and intended-host acceptance pass.

Public download assets have their own version, signatures and evidence. The
[`v0.5.6` release](https://github.com/devinkbrown/onyx-server/releases/tag/v0.5.6)
is a historical unsigned publication; it is not the current source or deployed
artifact. The historical publication procedure is retained below. Check an
asset's own manifest and verify any configured signer before using it. The
repository's [Dockerfile](Dockerfile) builds from a locally prepared release
artifact; it does not establish a published registry image.

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
supervisor kits run it before startup and before a Helix reload request.
The daemon itself also refuses an explicitly named unreadable or invalid config.
Preflight does not prove that the service sandbox permits reactor creation,
certificate loading or every intended listener; verify real runtime readiness.

## Quickstart (native)

**Build current source (0.10.0):**

```sh
packaging/release.sh
./dist/onyx-server-0.10.0-x86_64-linux-musl --check-config packaging/onyx-server.quickstart.toml
./dist/onyx-server-0.10.0-x86_64-linux-musl packaging/onyx-server.quickstart.toml
```

For a prebuilt download, use the asset version and checksum manifest from the
chosen GitHub Release. Do not guess a latest version from this guide or treat
an old public artifact as the current fleet release. Independent reproduction
requires the matching source commit, complete compiler distribution and build
metadata described below.

After startup, verify actual IRC/WebSocket registration and PONG. Build,
service state and listener presence are separate from client readiness.

- **`ws://localhost:8080`** — the browser WebSocket endpoint for the Onyx web client.
- **`irc://localhost:6667`** — plaintext IRC for any IRC client.

The node identity key (`onyx-server-node.key`) is loaded or generated beside
the selected config. The quickstart account store (`accounts.db`) resolves from
the working directory. Preserve both across subsequent starts; choose private
paths and stable node identity before joining a production mesh. For production, see [Production TLS card](#production-tls-card).

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
packaging/release.sh                                   # build a candidate → dist/
packaging/verify-release.sh dist/SHA256SUMS              # independent reproduction
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

Use the [canonical TLS/STS guide](../docs/guide/tls.md#production-tls-card)
for public DNS, trusted certificate paths, ACME, `wss`, optional TLS 1.2 and
kTLS behavior. The packaged quickstart binds plaintext IRC/WebSocket on `::`;
it is an evaluation config, not a public TLS deployment. Replace it with your
reviewed node-specific configuration and verify real hostname-checked TLS.
Keep certificate/key access compatible with the intended service account and
sandbox; a static config check is a separate gate from certificate loading.

## systemd (production UX)

OpenRC is the equivalent supported kit for Alpine and other OpenRC hosts.

Linux `zig build package` stages both supervisor kits. Install the kit for the
host's init system, provision its account/private state and preserve existing
operator overrides. Defaults and complete installation/reload/sandbox commands
live in [service management](../docs/guide/service-management.md). In particular,
reload validates the staged candidate before sending USR2, and request delivery
is separate from Helix completion.

The [release runbook](../docs/RUNBOOK.md) owns compatibility, custody, cold-restart
impact, recovery and rollback order. [Production paths](../docs/ops/onyx-server-paths.md)
owns installed host paths and current deployment constraints. Staging a package
neither installs nor enables a service and does not accept its runtime.

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
OIDC), producing `SHA256SUMS.sig`. For key-based verification, set `COSIGN_PUBKEY`.
For keyless verification, retain the emitted bundle and set both
`COSIGN_IDENTITY` and `COSIGN_OIDC_ISSUER`. A signature that is present but
not checked because the verifier or expected identity is absent is reported
as unverified; a checksum/rebuild pass does not authenticate its signer. If no signer is configured, release generation explicitly skips signing.
If a signer is configured and `cosign` is missing or signing fails, generation
fails; it does not silently publish an unsigned substitute.

### SBOM (CycloneDX)

`onyx-server.cdx.json` records the daemon and its Zig compiler as CycloneDX 1.5
metadata. The Linux static artifact has no separately packaged runtime libraries.
This emitted inventory does not audit the compiler distribution or replace
source, signature, reproducibility and intended-host acceptance checks.

### Provenance (SLSA v1 shape)

`onyx-server.provenance.json` is an in-toto Statement carrying an SLSA-provenance-v1
predicate. It records **what** was built (the artifact + its sha256), **from
what** (repo, ref, full commit), **how** (the exact `zig build …` command +
toolchain version), and **by whom** (the `release.sh` builder id). When a verified cosign signature covers `SHA256SUMS`, it also authenticates
the recorded provenance file's integrity. A local provenance statement and a
signature alone do not establish a SLSA build level or an isolated trusted
builder. Assess the actual builder, signer identity and release process separately.

## Historical first public GitHub Release (2026-07-20)

This section preserves the executed publication record for `v0.5.6`. Its
checks, asset names and unsigned status belong to that release; use the
current release scripts and new acceptance evidence for a new publication.

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
and download smoke are historical evidence for that artifact, not a substitute
for a verified signer or fresh acceptance of a different image.
