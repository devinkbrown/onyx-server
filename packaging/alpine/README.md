# Alpine signed package candidate

This is an isolated signed-APK development profile, not the accepted production
installation procedure. Use [Alpine operation](../../docs/guide/alpine.md) and
[service management](../../docs/guide/service-management.md) for the canonical
OpenRC kit. Production acceptance is tracked in [production paths](../../docs/ops/onyx-server-paths.md);
none of its results automatically accepts this candidate profile.

Build APKv3 only inside the disposable offline Alpine guest with a newly built
binary and an explicit ephemeral signing key. The v10 adapters require the
binary's `ONYX_HELIX_BOOT_POLICY=1` capability. Changed binaries and helpers
require fresh signed packages and a fresh native profile; the previous v9 run
supports only unchanged invariants. No host package installation or live host
operation belongs to this profile.

The package does not own or overwrite operator TOML, conf.d overrides, node
credentials or state. Provision a non-root runtime account and a private
0400/0600 config owned by that account. Root's identity-guard checks structural
config custody and the intended UID. The foreground OpenRC helper then invokes
`onyx-server --check-service-identity PATH` under the actual configured user,
group and working directory. This typed loader decides TOML, inline credentials,
actual `env:NAME` and `@file:PATH` references, and existing adjacent-key sources.
Shell adapters never parse or classify credential bytes. Key-bearing files must
meet the binary's private custody rules. Missing, malformed or inaccessible
sources refuse without generating a replacement identity.

The supervisor executes guarded-start, which repeats typed runtime preflight
and execs the fixed `/usr/bin/onyx-server --strict-existing-identity PATH`.
`RC_SVCNAME` is removed only for the ephemeral foreground start-stop-daemon
preflight; actual supervisor service context remains intact. The optional
upgrade helper applies the same typed runtime preflight before signed apk
installation. A custom OpenRC command override bypasses the wrapper and remains
outside this guarded-start contract.

Direct signed apk upgrades remain supported and preserve operator-managed
files; they do not start the daemon automatically. apk-tools 3.0.8 does not
provide the pre-upgrade refusal contract needed here, so no package trigger is
used to simulate it. The guest permits unrelated signed maintenance while a
service identity is absent. Local fixture installation uses
`--force-non-repository --network=no` for the diskless ISO cache policy and never
disables signature verification. Real diskless installations need their own
persistent repository/cache policy.

One new native profile builds and signs both versions, checks signature refusal
classes, byte/UID/GID/mode preservation and private captures, then exercises
file, inline, environment and referenced-file credential sources. A registered
IRC client remains on its original TCP socket during real SIGUSR2 Helix
self-exec. The guest checks both endpoint socket inodes, daemon PID/start time,
target executable inode, strict successor argv, explicit environment carry,
PONG participation and single registration. Key, realm and environment-reference
upgrade refusals must expose the specific existing sanitized error classes
`ChangedNodeIdentity`, `ChangedNodeRealm` and `ChangedBootEnvironment`, and retain
that predecessor and client before repaired source bytes permit the successful
upgrade. The environment refusal uses an initially present but unreferenced
binding with the same valid identity; a parse failure cannot satisfy it. The
successful exec must discard that unused binding. These are future acceptance assertions,
not proof obtained by authoring the harness. The original bounded five-second
probe retains BusyBox timeout exit 143 and a measured monotonic 4–10 second
window. The bounded file-source probe requires exactly one positive
`onyx-server: strict service identity source: existing_keyfile` banner; a
no-match, generated marker or read error fails. Host verification independently
checks the private capture. No generic timeout result establishes success.

Source review, fresh signed native execution and strict startup/Helix acceptance
remain required. This private candidate makes no full A04, crash rollback,
repository trust-distribution, release or deployment claim.

Source of truth: `make-apk.sh`, `identity-guard`, `runtime-preflight`,
`guarded-start`, `upgrade.sh`, and the binary's typed service-identity preflight.
Re-run the complete disposable guest profile whenever those inputs change.
