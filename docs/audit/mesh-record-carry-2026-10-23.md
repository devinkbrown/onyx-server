# Mesh record sizing and Helix frame continuity

Recovery baseline: `907db907757c3469795e557517665b5982317715`.

The reported symptom was recurring mesh failure with an oversized-message
error. The recovered baseline splits outbound encrypted mesh batches into
records of at most 1 MiB, reserves the complete output before advancing record
counters, and distinguishes `RecordTooLarge` from `HandshakeTooLarge`.

Independent review found a related regression: a record boundary can now split
an inner mesh frame. After authenticating the first record, its plaintext prefix
was held only in the inner decoder. Helix carried the encrypted receive buffer
and advanced counter but omitted that plaintext prefix. The successor could
authenticate the remaining record and then misinterpret its payload as a new
frame header.

The correction carries `inner_inbuf` through S2S snapshot schema v5, daemon
capture, and transactional link adoption. The carry must be an incomplete,
bounded frame; complete, oversized, truncated, or missing current fields fail
closed. Restoration copies bytes without dispatching frames or advancing
counters. Allocation failures free the candidate and preserve the predecessor.

Current whole-handoff validation requires schema v5. The private upgrade probe
advertises `s2s-inner-carry-v5` and omits incompatible predecessor lines, so
older images refuse the target before exec or descriptor inheritance. A first
deployment from the older live image requires an explicitly authorized rolling
cold restart. Fixed-image to fixed-image Helix retains the complete stream.

## Verification

Compiler: `/tmp/zig-017/zig-x86_64-linux-0.17.0/zig`, version `0.17.0`.
This compiler spells ReleaseSafe as `-Doptimize=safe`. The default `zig` wrapper
on this host reports unresolved CPU compatibility and was not used.

- Focused record/carry/snapshot/current-handoff Debug: 141 passed, no skips,
  failures, leaks, or log errors. ReleaseSafe: the same counts.
- Final Debug compatibility and carry selection: 167 passed, 5 platform skips,
  no failures, leaks, or log errors.
- Final ReleaseSafe upgrade-boundary, partial-frame allocation sweep, and live
  socket regression selection: 80 passed, no skips, failures, leaks, or log errors.
- Final source-bound ReleaseSafe mesh: 710 passed, 14 skips. Helix: 1,012
  passed, 75 skips. Both had zero failures, leaks, or log errors. The combined
  run completed in 676.7 seconds, including compilation.
- New daemon regression: real stream sockets and Ringlane receive completions
  capture both authenticated partial plaintext and a partial next encrypted
  record; successor adoption completes the signed membership exactly once.
  Duplicate membership repair does not emit another JOIN. Debug and ReleaseSafe
  passed.
- Allocation sweep covers every allocation in resumed-link construction and
  checks predecessor bytes against independent copies before successful retry.
- Independent read-only reviews approved the corrected leaf state, daemon
  capture/adopt seam, and both directions of the pre-exec compatibility boundary.

The full Debug suite is running against the frozen source at report creation.
Logs are in `/tmp/onyx-recovery-*.log`; deployment must wait for its final
result and independent release acceptance. Committing the unchanged source
allows reproducible packaging to run while that test finishes.

The static ReleaseSafe candidate built successfully (6/6 build steps) at
`zig-out/mesh-recovery/bin/onyx-server`. Its private upgrade probe emits the
current token only, and `--check-config` passed against the local live TOML.
This preliminary candidate identifies as `0.8.1+907db907757c-dirty`; it is not
a committed release artifact and has not been installed.

## Production state

Read-only checks on 2026-10-23 found both nodes with `links_active=1`,
`peers_up=1`, and `partitioned=0`. The local process advertised
`0.8.0+9ac4c9d0`; its executable SHA-256 was
`569a8c286907c098505550ec9e739fb4e5b5ec80d782aae834a966cba38167a9`.
Local supervision is OpenRC; the remote `onyx-server.service` is systemd and
was active. These observations are a baseline, not acceptance of the new fix.
OpenRC's service state was stopped despite the matching live local PID file;
the authorized rollout must reconcile that state without starting a duplicate.
The remote image SHA-256 was
`4aad53f36ad5f816e6cf2512597509df636dec2e4c1200791b832d30dd483af0`.

The user explicitly authorized deployment to both nodes and publication to
GitHub. Neither has occurred at report creation. Publish only after deployment
acceptance; retain the existing active relay epoch and roster configuration.
