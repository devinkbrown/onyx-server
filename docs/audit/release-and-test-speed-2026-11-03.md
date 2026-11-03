# Release and test-speed verification, 2026-11-03

The original production fix rollout accepted `0.9.0+c730d9f37b01`, built from clean commit
`c730d9f37b017a3e4c0a400c19cfa482a5198562`. The static x86-64 Linux musl
artifact reproduced byte-for-byte with SHA-256
`5735c08b3f537ee27b4d0c22ac7a80e96a6efc5b5122ba666f3d8e6ca3be5e61`.
The latest fleet refresh runs `0.9.0+5bdd9dc55d99` on both nodes, with
artifact SHA-256 `2dcc899051a71637116bbe270bf528fdff153b26ef4f68e136458eb56490c6c0`.
The original release evidence below retains its historical source binding;
the latest verification and rollout are recorded separately.

## Original production release evidence

Pinned compiler: Zig 0.17.0, SHA-256
`7c61539af19fa4082c94848f1c2b57b89e76dc6cfd5bd4c57764c3caf8f82272`.
The accepted production gates each executed 11,547 tests: 11,234 passed,
313 skipped, zero failures/leaks/log errors. Debug `all-checks` took
1,327.794 seconds; full ReleaseSafe took 1,889.844 seconds including its cold
compiler work. All shard inventories, raw log hashes, terminal exits, source
bindings and process cleanup were independently reviewed. Real release-artifact
TERM/INT daemon smokes and interactive setup signal controls also passed.

Retained local evidence:

- `.zig-cache/wave-162/full-debug-all-checks.json` and its raw log.
- `.zig-cache/wave-162/full-safe.json` and its raw log.
- `.zig-cache/wave-162/release-build.json` and `release-reproduce.json`.
- `.zig-cache/cloak-tmp/astra-release/final-gate-audit.json`.
- `.zig-cache/cloak-tmp/astra-release/artifact-smokes.json`.

## Full-suite speed

Commit `2dffe556960c1d9eff5fc78e753faf70d0b9666d` combines stable test-only
version metadata, validated duration profiles, exact-name shard manifests,
bounded RSA stress concurrency, and safe optional GnuTLS executable discovery.
Production version stamping and daemon behavior are unchanged by that commit.
Every unfiltered full release aggregate on supported native POSIX hosts uses the
exhaustive three-root parallel runner. Focused cached lanes select cases without
recompiling the root. Windows and cross targets retain their reference graphs.

| Complete Debug gate | Elapsed | Passed | Skipped | Executed |
|---|---:|---:|---:|---:|
| Production-source baseline `c730d9f3` | 1,327.794 s | 11,234 | 313 | 11,547 |
| Test improvements `2dffe556` | 944.273 s | 11,236 | 313 | 11,549 |

Elapsed time fell by 383.521 seconds (28.9%). This compares combined changes on
an uncontrolled shared host; it does not isolate scheduling as the cause. All
previous test names remain, the same 313 names skip, and two TLS controls were
added. Independent review checked all 12 shard inventories, binary/log hashes,
raw case sequences, footers and exits. The final `all-checks` completed 21/21
steps, including 115 ancillary fuzz/BoGo tests outside those three-root totals.

The test infrastructure controls passed 55 cases: 23 runner/profile, eight real
Git build-graph, and 24 ledger controls. The two new TLS controls also passed in
ReleaseSafe. The complete new Debug gate ended with unchanged inputs and no
owned processes remaining.

Evidence: `.zig-cache/wave-163/full-debug-duration.json`,
`.zig-cache/wave-163/test-infrastructure-controls.json`, and
`.zig-cache/cloak-tmp/astra-release/test-speed-final-review.json`.

Cold ReleaseSafe compilation remains a material cost. A compile-only filtered
experiment took 1,388.244 seconds and ran no tests; it did not justify replacing
the verified build graph with an unproven partition. Reuse cached artifacts and
source-bound accepted evidence rather than repeating unchanged broad gates.

## Documentation follow-up and TLS test observer correction

Commit `5bdd9dc55d99527a9195883b392f8a7e93d90a2e` includes the source-backed
documentation overhaul and a test-only TLS clean-close correction. The previous
observer stopped when the server connection row disappeared, even though the
peer could still have unread authenticated ciphertext. The corrected fixture
withholds peer application reads until retirement, then drains through actual
EOF. Exact prefix, one KeyUpdate reply and exact suffix ordering remain required;
positive reads after retirement make the old observation point insufficient.
Production TLS behavior is unchanged.

The first full documentation gate found this race and was cancelled after the
failure was diagnosed. It supplies no full-suite acceptance. A debugger negative
control on the corrected binary emulates the premature observation by forcing
its local EOF flag after the first post-retirement read: the assertion fails
with only 1,024 ciphertext bytes observed and no complete 32 KiB prefix. This is
a controlled emulation, not an old-binary or production failure reproduction.
The unmodified corrected test passed all six cipher-suite/RX combinations in
both Debug and ReleaseSafe. Each focused gate reports 90 passes, comprising
one substantive test and 89 import/discovery anchors.

The corrected complete Debug `all-checks` gate passed in **911.902 seconds**:
**11,236 passed, 313 skipped, 11,549 executed**, no failures/leaks/log errors.
All 12 shard logs, exact names, skip sets, binary hashes and source bindings
were independently checked; coverage matches the accepted `2dffe556` inventory.
The build completed 21/21 steps and 115 ancillary tests. Inputs remained
unchanged and no owned processes remained. This elapsed time is another
shared-host observation, not an isolated performance attribution.

ReleaseSafe evidence is explicitly combined: the accepted full `c730d9f3`
gate, two later TLS preflight controls, a fresh 142-pass configuration gate,
and the fresh clean-close observer gate. Independent review read every source
and build delta: the only executable production statement change after
`c730d9f3` is a configuration diagnostic prefix, covered by the configuration
gate; other source changes are test code or comments. Production revision
stamping remains intact. **No full ReleaseSafe run of `5bdd9dc5` is claimed.**

Receipts: `.zig-cache/wave-164/docs-fixed-full-debug.json`,
`docs-overhaul-config-safe.json`, `tls-close-observer-debug.json` and
`tls-close-observer-safe.json` in the same directory; the precise fix proof is
`.zig-cache/tls-close-repro-2c810283/fix-proof.json`.

## Live acceptance and service kits

OpenRC now supervises the foreground daemon under the configured identity,
validates before start/reload, bounds restart/stop behavior, and uses a private
working directory. systemd uses the canonical kit with host-specific account,
path, limit and public-feed permission overrides. Kit correction `6131c4de`
keeps protected `openat2` certificate loading available: systemd's separate
`RestrictSUIDSGID` filter otherwise returns `ENOSYS`. The first peer attempt was
rolled back before an isolated A/B probe established this cause. The corrected
unit passed the native parser and all seven service checks before retry.

Both cold restarts recovered durable account tokens issued before deployment.
Four CA-verified TLS clients passed 13 channel/DM exact-one event checks with
matching message IDs and timestamps, local exact attachment resume on both
origins, and peer redirect followed by origin restore. Dedicated generated
accounts were then removed. This does not prove arbitrary-node exact attachment
restore, old composite-token continuity across cold restart, or production Helix.
The configured WebTransport listener still requires cold upgrades.

Before each cold boundary, ordered same-origin sentinels established acceptance
of an earlier prefix followed by an observed quiet window. This is not a proof
that global MESSAGE_V2 custody was empty or that later producers were fenced.

Runtime paths and health facts: [production paths](../ops/onyx-server-paths.md).
Receipts are retained under `.zig-cache/cloak-tmp/astra-release/`, including
`live-acceptance-receipt.json`, `peer-cert-sandbox-ab.json`, and
`peer-corrected-kit-native-verification.json`. Private account/token files are
excluded from tracked documentation.

## Latest fleet refresh: `5bdd9dc5`

The user separately authorized deployment after the observer correction. Clean
commit `5bdd9dc55d99527a9195883b392f8a7e93d90a2e` built in 465.714 seconds;
a second clean-worktree, clean-cache build reproduced it in 452.586 seconds.
Both outputs have SHA-256
`2dcc899051a71637116bbe270bf528fdff153b26ef4f68e136458eb56490c6c0`
and embed `0.9.0+5bdd9dc55d99`. Build inputs, all four manifest entries,
static musl/baseline compiler metadata, source equality and process cleanup
were independently checked. Local provenance is unsigned; no signature or
SLSA-level attestation is claimed. Real artifact TERM and INT smokes each
passed 19 checks, and interactive setup passed both signal controls.

Fresh rollback captures preceded installation on both nodes. Both unchanged
node-specific TOMLs passed staged and installed checks as the service users.
The OpenRC and corrected systemd kits, host overrides, working directories,
limits and public-feed umasks were preserved. Each predecessor's exit was
observed before accepting its replacement. The services were restarted one at
a time; current boot logs confirmed TLS, kTLS TX+RX, WebTransport and secured
mesh establishment, and the intended listeners were present.

Durable account tokens issued before the cold boundary authenticated after
restart on both nodes. Four CA/hostname-verified TLS clients passed 13 events
with exact counts, message IDs and timestamps, local exact attachment restore,
and peer redirect followed by origin restore. Both generated accounts were
removed. This repeats the scoped acceptance above; it does not establish old
composite-token cold continuity, arbitrary-node exact restore, production Helix,
or globally empty custody. Ordered-prefix and quiet-window observations remain
qualifications rather than a global producer fence.

Final health on both nodes was `tcp_active=1`, `links_active=1`, `peers_up=1`,
`partitioned=0`, with the existing ActiveV2 epoch 1, roster count 2 and digest
unchanged. Local PID 774 (OpenRC supervisor 773) and peer PID 2822304 ran the
verified image; the peer reported zero automatic restarts. Status and backup
feeds returned HTTPS 200 with valid fresh JSON; all three checked public files
remained mode 0644. Private config and fixture credential files remained 0600.

The final receipt is
`.zig-cache/cloak-tmp/astra-release-5bdd9dc5/final-deployment-receipt.json`,
SHA-256 `dc01161e859ffd79c2b16ceb2d60c9e189419994ea050689739d773e7f4920b2`.
Related acceptance, node snapshots, restart observations, public-feed checks
and artifact smokes are in that same local evidence directory. Private
credentials are excluded from the tracked record. Current paths and image
identity are maintained in the [fleet record](../ops/onyx-server-paths.md).
