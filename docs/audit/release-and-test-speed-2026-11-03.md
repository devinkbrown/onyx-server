# Release and test-speed verification, 2026-11-03

Both production nodes accepted `0.9.0+c730d9f37b01`, built from clean commit
`c730d9f37b017a3e4c0a400c19cfa482a5198562`. The static x86-64 Linux musl
artifact reproduced byte-for-byte with SHA-256
`5735c08b3f537ee27b4d0c22ac7a80e96a6efc5b5122ba666f3d8e6ca3be5e61`.
Later commits change test infrastructure, service kits and documentation; the
running daemon retains its actual artifact revision.

## Release evidence

Pinned compiler: Zig 0.17-dev, SHA-256
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
