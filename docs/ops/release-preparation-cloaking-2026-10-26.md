# Cloaking and integration release preparation

2026-10-26 · candidate working-tree changes · not a deployed release

The source manifest remains 0.8.1. The starting HEAD is
`066d9b8356bee1fda345eea3fae35ef132397956`, with pre-existing user changes
preserved. No commit, tag, push, live configuration edit, service-manager
change, or production deployment is represented by this record.

## Current release gate — 2026-10-27

The independent [Astra investigation](../audit/onyx-astra-investigation-2026-10-27.md)
found policy fail-open paths, durable/live AKICK divergence, media-worker failure
admission, an offer-publication race, and missing media retirement. Release
acceptance remains blocked by AKICK and the broader retirement work.

The unchanged baseline full Debug run finished with 10,420 passes, 323 skips and
six failures out of 10,749 tests. Five failures were stale Helix fixture suffixes;
the remaining native-worker failure led to a deterministic first-bind race
reproduction and settlement-barrier fixture correction.

Reviewed prefix, worker-failure, offer-publication and fixture corrections are
now in the candidate source. Their combined gate passed 157 tests with two skips
in both Debug and ReleaseSafe, with unchanged-source receipts and no failures,
leaks or log errors. Native and OpenBSD non-test semantic checks passed; this
does not establish native OpenBSD runtime acceptance. The full suite has not
been rerun green on this new source cut.

The setup allocation sweep also uses explicit test-only KDF entries now. It
reaches the same clean allocation index, 222, as the original full-cost sweep;
Debug sweep runtime was 6.163 seconds. Ordinary production factors remain
100,000, and default cold authentication plus verifier metadata are tested.
Non-test compilation checks prove the four reduced-factor callables unavailable.

AKICK's isolated leaf passed 110 tests in both modes; its expanded leaf/Helix
cut passed 125 in Debug and its new delta passed 95 in ReleaseSafe. These do not
prove command-level enforcement. The broader retirement draft is held back
until ordinary active-call departure preserves IRC and unaffected calls while
denying the selected media. Captured-artifact QUIT leakage has been reproduced
with actual TLS EOF and fresh authenticated UDP. Exact source cuts, logs and
receipts are under `.zig-cache/wave-7/`; historical gates below do not certify
the current expanded candidate or a deployed release.

## Implemented candidate

- Fourteen-day default anonymous rotation and v4 opaque cloaks binding the
  canonical address/family, epoch, cadence, and normalized suffix to a
  128-bit HMAC-SHA256 token.
- Allocation-free historical policy matching with bounded current/previous-key
  derivations across channel lists, ACCESS, SACCESS, AKICK, and WARD. Secured
  remote matching binds origin node, full prefix, account, and existing private
  roster data.
- Collision-resistant encoding for account names that cannot safely retain a
  canonical DNS label, while normal canonical account cloaks stay compatible.
- Self-claim ownership enforcement at creation, durable restoration, USE,
  fanout, and inherited application. Unsafe historical claims are rejected
  transactionally; explicit operator-granted authority remains distinct.
- Requested key derivation fails closed; blank configured secrets and invalid
  suffixes are rejected. Mapped IPv4 is normalized before address consumers.
- `VHOST OFF` recomputes the configured cloak instead of exposing the address;
  explicit personas cannot impersonate reserved generated-host namespaces.
- All-platform mandatory Helix preservation of ACCESS, SACCESS, AKICK, and
  WARD, with staged decode/configuration validation, no-fail commit, exhaustive
  allocation rollback coverage, and a new pre-exec capability boundary.
- Bounded bitmap iteration without repeated per-value whole-map searches or
  large union copies. Small/medium sets use a bounded per-chunk fallback.
- Linux package staging includes OpenRC supervision assets and a configuration
  template, with startup validation and bounded respawn. No service is installed
  or started by package staging.
- Release and verification scripts use `--release=fast`, avoiding the optimizer
  enum spelling difference between stable and development Zig. Clean-tree and
  reproducibility guards remain intact.
- Protected-media fixtures initialize the real module runtime. Receive-failure
  coverage drives genuine terminal completions, bounded accepted output, and
  EOF. The existing terminal PING catch now records its actual typed failure
  exactly once before the existing close transition.

The [integrated roadmap](../ROADMAP-2026-10-26.md) contains 98 deliverables for
setup, usability, tokens, media, mesh, Alpine, and measured efficiency. The
[client outline](../design/onyx-client-integration-2026-10-26.md) defines proposed
client journeys and server contracts. Those documents do not claim that the
wizard, media upgrades, or client changes are implemented by this slice.

## Verification record

Native compiler: `/tmp/zig-017/zig-x86_64-linux-0.17.0/zig`, version **0.17.0**.
This compiler uses `-Doptimize=safe` for ReleaseSafe. The default `zig` wrapper
and the older staged development compiler are not the verification toolchain.

| Gate | Result | Evidence under `.zig-cache/` |
| --- | --- | --- |
| Focused server integration | Debug 93/93; safe 93/93 | `cloak-evidence/server-debug.log`, `server-safe.log` |
| Combined critical modules | safe 263/263; no skips, failures, leaks, or log errors | `cloak-evidence/critical-safe.log` |
| Final combined critical gate | safe module 294 passed, 1 skipped / 295; executable 3/3 passed; zero failures/leaks/log errors | `cloak-evidence/critical-safe-accepted.log` |
| Wildcard cloak edge cases | Native Debug 46/46; safe 46/46 | `cloak-glob-debug.log`, `cloak-glob-safe.log` |
| Protected media/receive integration | Debug 110 passed, 1 skipped; safe 110 passed, 1 skipped, 111 total each | `cloak-evidence/release-fixtures-debug.log`, `release-fixtures-safe.log` |
| Mandatory handoff relations | Debug 94/94; safe 94/94 | `cloak-relations-debug.log`, `cloak-relations-safe.log` |
| Guise/durable provenance | Debug 94/94; safe 94/94 | `cloak-grant-debug.log`, `cloak-grant-safe.log` |
| Requested-key failure | Debug 3/3; safe 3/3 | Initial logs `/tmp/onyx-cloak-main-native-{debug,safe}.log` |
| Configuration | 425 passed, 4 skipped, 429 total | `cloak-config-debug.log` |
| Bitmap iteration | Debug 89/89; safe 89/89 | `cloak-evidence/bitmap-debug.log`, `bitmap-safe.log` |
| Final unfiltered Debug suite | Pass: module 10,234 passed, 322 skipped / 10,556; executable 54/54; CLI 14/14; zero failures/leaks/log errors | `cloak-evidence/full-debug-accepted.log` |
| Final package and semantic check | Pass; package/check 10/10 steps | `cloak-evidence/package-accepted.log` |
| Aarch64 Linux/musl semantic check | Pass; 3/3 steps, cross-check only | `cloak-evidence/check-aarch64-accepted.log` |
| Packaged config/capability smoke | Pass; quickstart validation and mandatory policy capability | `cloak-evidence/package-config.log`, `package-capability.txt` |
| Changed-source formatting and diff whitespace | Pass | `cloak-evidence/fmt-owned-final.log`, `diff-check.log` |
| Repository-wide formatting | Fails on 197 files outside this task's source ownership | `cloak-evidence/fmt.log` |

Focused counts overlap imported tests and must not be added together as a
unique-test total. Superseded in-flight test cuts were stopped when essential
security/performance changes invalidated them; they are not accepted final
suite evidence. Complete logs remain separate from concise progress reports.

The final frozen source-content manifest covers 1,076 files, including the two
release scripts:
`.zig-cache/cloak-evidence/source-frozen.sha256`, manifest SHA-256
`79c1d24b8d3b534db4ea5aa77856139c7813e23ec12cbd73d08948ef228f4d0e`.
Recheck the manifest after gates. This identifies the tested working tree; it
does not make a dirty tree into a reproducible official release.

Package completion was checked against the unchanged manifest. OpenRC script
mode is 0755 and the configuration template mode is 0644. The daemon was invoked
only for side-effect-free configuration and capability probes, not started.
Release-script syntax and the native compiler's fast-mode build plan were also
validated; an actual reproducible release build remains gated on clean source.

The final complete Debug invocation exited 0, with 9/9 build steps and 10,624
tests across all three artifacts: **10,302 passed, 322 skipped, zero failures,
leaks, or log errors**. Module runtime was 2,510.788 seconds. The frozen manifest
was verified unchanged afterward. The staged candidate binary SHA-256 is
`36e9d815fc33780ce4ee27349059ca59504f60e20bc05376e6b21078ed1203a4`.
It remains a working-tree build rather than an official reproducible release.

The preceding unfiltered cut exposed eight protected-media failures and one
receive test failure. Exact pre-cloaking server reconstruction reproduced the
failures. Media fixtures were cold because they bypassed actual startup; receive
coverage assumed immediate EOF despite accepted output and outstanding kernel
ownership, then exposed the separate missing PING diagnostic. Baseline proof
and narrow review diffs are retained under `cloak-evidence/`. The repaired
fixtures retain the original security/ownership assertions. Their one skip is
the kernel-epoch protected-media getter test, which remains an external
capability/acceptance concern rather than a claimed pass.

That preceding full run completed 10,555 module tests: 10,223 passed, 322
skipped, and 10 failed, plus 54 passing executable and 14 passing CLI tests.
Its tenth failure was the unchanged retained-mesh successor-compaction SIGKILL
test timing out in its child watchdog. The exact isolated Debug replay passed
all 556 prefixes in 102.564 seconds (81/81 including imported tests), with disk
journal waiting observed. This is an unresolved intermittent gate failure,
not a proven data-corruption diagnosis or a resolved bug. Preserve the original
timeout and assertions and retain this history. The subsequent complete final
run passed all 556 successor prefixes with the original watchdog. This clears
that gate for the recorded cut, but does not establish that the earlier
intermittent timeout's cause was fixed. Evidence:
`cloak-evidence/mesh-audit-exact-debug.log` and `full-debug-accepted.log`.

Independent GPT-6.1 Sol medium reviews approved the final cloak integration
and final bitmap delta. A prior review found the historical claimed-persona
bypass; it was reproduced, fixed, and then independently reviewed again.

The server regressions exercise real Mooring/AEAD/signed-frame receiver paths,
positive delivery before denial, suppression under the historical mask, and
delivery after deletion. Helix tests use actual mandatory seal/adopt and sweep
allocation failures through the first uninjected success, comparing all four
encoded stores on failure and success. These are meaningful daemon fixtures;
they do not replace external distinct-host production acceptance.

## Measured bitmap workloads

Same native Debug compiler/flags and unchanged data/checks for each before/after
pair, one timing per side. These are workload measurements, not statistically
established service-level speedups.

| Workload | Before | Final |
| --- | --- | --- |
| Existing 6,000-iteration random-set oracle | 25.25 s | 1.41 s |
| 100,000 complete tiny traversals | 1.19 s | 0.18 s |
| 100 complete traversals of 65 sparse containers | 0.09 s | 0.03 s |
| 100 complete traversals of 513 sparse containers | 2.08 s | 1.75 s |

An intermediate threshold caused a substantial 65-container regression. It was
measured, corrected before freezing, and covered by an operation-count
regression. No daemon-wide throughput or media-quality improvement is claimed.

## Required migration and release work

1. **Legacy masks:** inventory all existing rule stores before rollout. V4
   retains provenance for future rotations; arbitrary unlabeled old opaque
   masks cannot reveal their original epoch/cadence. Do not silently guess
   grants or claim an automatic indefinite migration for those records.
2. **Historical personas:** audit old self-claims. An unsafe restored wardrobe
   is refused; authorized repair must distinguish an account's own identity
   from an explicit operator grant. Skipping the failed restore is not a
   compatible Helix migration.
3. **Actual configuration:** existing explicit `anon_epoch_secs = 86400` remains
   daily. A reviewed rollout must change it to `1209600` on every participating
   node without changing the shared secret accidentally.
4. **Key and suffix retention:** historical matching requires the relevant
   current/previous key and suffix. Dropping them has an explicit policy impact.
5. **Mixed nodes:** nodes lacking the matcher/private roster cannot promise v4
   policy continuity. Verify the whole participating mesh before claiming the
   new contract; no new mesh-wide activation capability is implemented here.
6. **Helix boundary:** `mandatory-policy-v1` refuses predecessors that omit
   policy stores before exec. Do not bypass the probe. Establish a compatible
   migration path or obtain explicit authorization for an accepted-loss cold
   boundary before any production action.
7. **Cold persistence:** this slice fixes Helix preservation. IRCX channel
   ACCESS cold-restart persistence remains a separate gap; do not describe
   mandatory capsules as a new durable disk store. Existing durable mirrors
   for other stores retain their own contracts.
8. **Baseline debt:** resolve or separately scope the repository-wide
   formatting debt. A pre-existing bitmap bitset-demotion path also mutates
   membership before a potentially failing allocation; iteration changes do
   not fix or certify that mutation's atomicity.
9. **Clean provenance:** produce one coherent reviewed release revision without
   accidentally committing unrelated user work. Run deterministic release and
   reproducible package verification; ordinary dirty-tree package staging is
   insufficient.
10. **External acceptance:** verify the authorized deployment strategy, rollback
    capture, both-node configuration, actual client/session/media behavior, and
    secured mesh health. GitHub publication follows green acceptance.

The release remains a preparation candidate until these applicable conditions
and the final gates are resolved. The [Alpine guide](../guide/alpine.md)
describes staged assets and operational prerequisites; it does not claim a
completed OpenRC installation or a production operating-system migration.
