#!/usr/bin/env bash
# Build an attested, optionally signed Onyx Server release candidate.
#
# Builds a static ReleaseFast binary for x86_64-linux-musl or
# aarch64-linux-musl. Reproducibility requires independent verification with
# the same source, compiler and recorded flags. This script emits:
#
#   * SHA256SUMS            — integrity manifest over ALL artifacts (binary first)
#   * onyx-server.cdx.json       — a one-screen CycloneDX SBOM
#   * onyx-server.provenance.json — an SLSA-provenance-v1-shaped build attestation
#   * SHA256SUMS.sig        — a cosign signature over SHA256SUMS (when configured)
#
# The SBOM has no timestamps; provenance pins its build times + ref to the SOURCE
# COMMIT (not wall-clock or the local branch) to support repeat builds.
# `verify-release.sh` independently checks the binary and other artifacts
# against the manifest.
#
# Graceful degradation (no network, no hard tool deps):
#   * cosign absent / unconfigured → signing is skipped with a note (never fails).
#   * jq   absent                  → JSON validation is skipped with a note.
# Requires `git`, `zig`, `sha256sum`, and Python 3.
#
# Usage: packaging/release.sh [output-dir] [target] (one target per directory)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

OUT="${1:-dist}"
TARGET="${2:-x86_64-linux-musl}"
case "$TARGET" in
  x86_64-linux-musl) ARCH=x86_64 ;;
  aarch64-linux-musl) ARCH=aarch64 ;;
  *) echo "release: unsupported target" >&2; exit 2 ;;
esac
CPU=baseline
REPO_URL="https://github.com/devinkbrown/onyx-server"

# A clean tree gives a clean `<semver>+<hash>` version (no `-dirty` suffix), which
# is what makes the artifact reproducible for anyone building the same commit.
if ! GIT_STATUS="$(git status --porcelain 2>/dev/null)"; then
  echo "release: cannot inspect working tree" >&2
  exit 1
fi
if [ -n "$GIT_STATUS" ]; then
  echo "release: refusing to build — working tree is dirty (version would be -dirty, not reproducible)" >&2
  exit 1
fi

COMMIT="$(git rev-parse --short HEAD)"
FULLSHA="$(git rev-parse HEAD)"
# The provenance ref is a pure function of the commit — NOT the local branch or
# detached-HEAD state — so two people building the identical commit emit
# byte-identical provenance (and therefore SHA256SUMS). The commit is the
# authoritative source identity; the transient branch name is not recorded.
REF="refs/commits/${FULLSHA}"
VERSION="$(grep -oE '\.version = "[^"]+"' build.zig.zon | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
ARTIFACT="onyx-server-${VERSION}-${TARGET}"
ZIG_BIN="$(command -v zig)"
ZIGVER="$("$ZIG_BIN" version)"
ZIG_SHA256="$(sha256sum "$ZIG_BIN" | cut -d' ' -f1)"
[[ "$FULLSHA" =~ ^[0-9a-f]{40,64}$ && "$ZIG_SHA256" =~ ^[0-9a-f]{64}$ && "$VERSION" =~ ^[0-9A-Za-z.+_-]+$ && "$ZIGVER" =~ ^[0-9A-Za-z.+_-]+$ ]] || { echo "release: invalid metadata" >&2; exit 1; }

# Pin build metadata to the source commit so the whole release is reproducible:
# the binary already embeds only <semver>+<commit>, and the provenance below uses
# the commit's committer date rather than the wall clock.
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || { echo "release: invalid commit time" >&2; exit 1; }
COMMIT_ISO="$(git show -s --format=%cI HEAD)"
# The standard release switch works with both development and stable Zig enum
# spellings (ReleaseFast versus fast) without weakening the selected mode.
BUILD_CMD="zig build -Dtarget=${TARGET} -Dcpu=${CPU} --release=fast"

echo "release: building ${ARTIFACT} @ ${COMMIT} (static ReleaseFast; verification required)…"
CACHE="$(mktemp -d)"
trap 'rm -rf "$CACHE"' EXIT
"$ZIG_BIN" build "-Dtarget=$TARGET" "-Dcpu=$CPU" --release=fast --cache-dir "$CACHE" --prefix "$CACHE/out"

mkdir -p "$OUT"
cp "$CACHE/out/bin/onyx-server" "$OUT/$ARTIFACT"
chmod 755 "$OUT/$ARTIFACT"

SIZE="$(stat -c%s "$OUT/$ARTIFACT")"
DIGEST="$(sha256sum "$OUT/$ARTIFACT" | cut -d' ' -f1)"

# Machine-readable reproduction inputs, included in SHA256SUMS below.
python3 - "$OUT/onyx-server.build.json" "$TARGET" "$ARCH" "$CPU" "$VERSION" "$FULLSHA" "$ZIGVER" "$ZIG_SHA256" "$ARTIFACT" "$DIGEST" "$SOURCE_DATE_EPOCH" <<'PYMETA'
import json, sys
path, target, arch, cpu, version, commit, zigver, zigsha, artifact, digest, epoch = sys.argv[1:]
with open(path, 'w', encoding='utf-8') as out:
    json.dump({'format': 1, 'target': target, 'architecture': arch, 'cpu': cpu,
               'version': version, 'commit': commit, 'zig_version': zigver,
               'zig_sha256': zigsha, 'artifact': artifact, 'sha256': digest,
               'source_date_epoch': epoch,
               'flags': ['build', '-Dtarget=' + target, '-Dcpu=' + cpu, '--release=fast']}, out, sort_keys=True, indent=2)
    out.write('\n')
PYMETA

# --- One-screen CycloneDX SBOM ------------------------------------------------
# Genuinely one screen: the dependency graph is a single self-contained binary
# with zero external components. The only "component" is the Zig toolchain that
# produced it, recorded as a build tool (not a runtime dependency).
cat > "$OUT/onyx-server.cdx.json" <<JSON
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": {
    "component": {
      "type": "application",
      "name": "onyx-server",
      "version": "${VERSION}+${COMMIT}",
      "description": "Clean-room, pure-Zig, zero-external-dependency IRC/IRCX mesh daemon with its own TLS 1.3 stack.",
      "licenses": [{ "license": { "id": "AGPL-3.0-or-later" } }],
      "purl": "pkg:generic/onyx-server@${VERSION}?arch=${ARCH}&os=linux&libc=musl"
    },
    "tools": [{ "vendor": "ziglang", "name": "zig", "version": "${ZIGVER}" }],
    "properties": [
      { "name": "onyx-server:reproducibility", "value": "verification_required" },
      { "name": "onyx-server:target", "value": "${TARGET}" },
      { "name": "onyx-server:linkage", "value": "static" },
      { "name": "onyx-server:commit", "value": "${FULLSHA}" },
      { "name": "onyx-server:sizeBytes", "value": "${SIZE}" }
    ]
  },
  "components": [],
  "properties": [
    { "name": "onyx-server:externalDependencies", "value": "0" },
    { "name": "onyx-server:sha256", "value": "${DIGEST}" }
  ]
}
JSON
echo "release: SBOM → $OUT/onyx-server.cdx.json (0 external components)"

# --- SLSA provenance (in-toto Statement v1 / SLSA provenance v1 predicate) -----
# Hand-authored to the SLSA v1.0 provenance shape. It records WHAT was built (the
# artifact + its digest), FROM WHAT (source repo, ref, full commit), HOW (the
# exact build command + toolchain), and BY WHOM (this script as the builder).
# Timestamps are the commit's committer date, keeping the document reproducible.
#
# Trust level: this is SLSA-provenance-shaped and, once cosign-signs SHA256SUMS
# (which lists this file's digest), AUTHENTICATED — the local-builder equivalent
# of L2. Running the same steps on a hosted runner (e.g. the slsa-github-generator
# GitHub Action) with an isolated builder identity is what elevates it to true
# SLSA L2/L3; the field shapes here are drop-in compatible with that upgrade.
cat > "$OUT/onyx-server.provenance.json" <<JSON
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "${ARTIFACT}", "digest": { "sha256": "${DIGEST}" } }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://onyx-server.build/zig-static-musl/v1",
      "externalParameters": {
        "source": "${REPO_URL}",
        "ref": "${REF}",
        "commit": "${FULLSHA}",
        "target": "${TARGET}",
        "cpu": "${CPU}",
        "optimize": "ReleaseFast",
        "buildCommand": "${BUILD_CMD}"
      },
      "internalParameters": {
        "zigVersion": "${ZIGVER}",
        "zigSha256": "${ZIG_SHA256}",
        "sourceDateEpoch": "${SOURCE_DATE_EPOCH}"
      },
      "resolvedDependencies": [
        {
          "uri": "git+${REPO_URL}@${REF}",
          "digest": { "gitCommit": "${FULLSHA}" }
        }
      ]
    },
    "runDetails": {
      "builder": {
        "id": "${REPO_URL}/packaging/release.sh",
        "builderDependencies": [
          { "uri": "pkg:generic/zig@${ZIGVER}", "name": "zig", "version": "${ZIGVER}" }
        ]
      },
      "metadata": {
        "invocationId": "${FULLSHA}",
        "startedOn": "${COMMIT_ISO}",
        "finishedOn": "${COMMIT_ISO}"
      },
      "byproducts": [
        { "name": "onyx-server.cdx.json", "mediaType": "application/vnd.cyclonedx+json" }
      ]
    }
  }
}
JSON
echo "release: provenance → $OUT/onyx-server.provenance.json (SLSA provenance v1 shape)"

# Validate the emitted JSON when jq is available. A malformed doc is OUR bug, so
# fail loudly; when jq is absent we degrade to a note rather than blocking.
if command -v jq >/dev/null 2>&1; then
  for j in onyx-server.cdx.json onyx-server.provenance.json; do
    jq empty "$OUT/$j" || { echo "release: FATAL — $j is not valid JSON" >&2; exit 1; }
  done
  echo "release: JSON validated (jq)"
else
  echo "release: jq not found — skipping JSON validation (install jq to validate SBOM/provenance)"
fi

# --- Integrity manifest -------------------------------------------------------
# The binary is listed FIRST so `verify-release.sh` can read it as line 1. The
# SBOM and provenance are included too, so a single cosign signature over
# SHA256SUMS anchors the entire release.
( cd "$OUT" && sha256sum "$ARTIFACT" "onyx-server.build.json" "onyx-server.cdx.json" "onyx-server.provenance.json" > SHA256SUMS )
echo "release: SHA256SUMS →"
sed 's/^/release:   /' "$OUT/SHA256SUMS"

# --- Optional signing: keyless (CI OIDC) or a cosign key file -----------------
# Fail-closed on INTENT: if a signer is configured but cosign is missing, that is
# a hard error (never silently ship the unsigned release the user asked to sign).
# Only when NO signer is configured do we skip — that path is the graceful one.
if [ -n "${COSIGN_KEY:-}" ] || [ -n "${COSIGN_EXPERIMENTAL:-}" ]; then
  if ! command -v cosign >/dev/null 2>&1; then
    echo "release: FATAL — a signer is configured (COSIGN_KEY/COSIGN_EXPERIMENTAL) but cosign is not installed" >&2
    exit 1
  fi
  echo "release: cosign-signing SHA256SUMS…"
  if [ -n "${COSIGN_KEY:-}" ]; then
    cosign sign-blob --yes --key "$COSIGN_KEY" --output-signature "$OUT/SHA256SUMS.sig" "$OUT/SHA256SUMS"
  else
    # Keyless (Fulcio/Rekor via OIDC): emit a bundle so verify-release.sh can
    # check the signer identity without a long-lived public key.
    COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes \
      --output-signature "$OUT/SHA256SUMS.sig" \
      --bundle "$OUT/SHA256SUMS.cosign.bundle" "$OUT/SHA256SUMS"
    echo "release: keyless bundle → $OUT/SHA256SUMS.cosign.bundle"
  fi
  echo "release: signature → $OUT/SHA256SUMS.sig"
else
  echo "release: no signer configured — skipping signature (set COSIGN_KEY=<key> or COSIGN_EXPERIMENTAL=1 for keyless OIDC)"
fi

echo "release: done → $OUT/ (${ARTIFACT}, SHA256SUMS, onyx-server.cdx.json, onyx-server.provenance.json)"
