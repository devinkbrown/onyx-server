# Onyx Server 0.5.6 certificate-session release record

Deployment date: 2026-07-19

This is the executed two-node release record for certificate-backed SASL
EXTERNAL session resume. It records observed production paths, including legacy
unit and binary names; those literals are not new product naming.

> **Historical snapshot (2026-07).** The paths and unit names below are immutable
> evidence for that release. Current production uses `onyx-server.service` and
> `/home/kain/onyx-server-run` / `/home/trev/onyx-server-run`; see
> [`onyx-server-paths.md`](onyx-server-paths.md).

## Immutable release inputs

| Item | Value |
|---|---|
| Release commit | `8eaaedbc22e6` |
| Version banner | `Onyx Server 0.5.6+8eaaedb` |
| Artifact | `onyx-server-0.5.6-x86_64-linux-musl` |
| Artifact SHA-256 | `5f02720a6b150282ff75c797fd6e19f651796f98b3248cd05fa1d988fbdd6bc4` |
| Packaging result | clean-cache rebuild byte-identical to published artifact |
| Reviewer | fresh structured security review, verdict `pass`, no findings |

The detached clean worktree passed `zig build all-checks --summary all`: 18/18
steps, 7,808 tests passed, 4 skipped, zero failed. The affected ReleaseSafe
server, session, mesh, and Helix suites also passed, followed by `zig build
check` and `git diff --check`.

## Live node inventory and rollback

| | `eshmaki.me` | `ircx.us` |
|---|---|---|
| Deploy order | second | first |
| Live unit | `orochi.service` | `orochi.service` |
| Live binary | `/home/kain/orochi-run/orochi` | `/home/trev/orochi-run/orochi` |
| Config | `/home/kain/orochi-run/orochi.local.toml` | `/home/trev/orochi-run/orochi.ircxus.toml` |
| Previous banner | `0.5.6+984a74a` | `0.5.6+984a74a` |
| Previous SHA-256 | `34b650bff7a45d0ba1461954bbddcb42a9b43ce479c16c3650012b02c720f0ac` | same |
| Binary rollback | `orochi.predeploy-8eaaedb` | `orochi.predeploy-8eaaedb` |
| Config rollback | `orochi.local.toml.predeploy-8eaaedb` | `orochi.ircxus.toml.predeploy-8eaaedb` |

The feature introduced no configuration key. Each existing production config
was preserved byte-for-byte and passed the staged `0.5.6+8eaaedb` binary's
`--check-config` before either live binary was replaced.

Rollback, if required, is a hard restart using the corresponding explicit
`predeploy-8eaaedb` binary and config. Do not infer compatibility with an older
Helix image; this release was intentionally activated by hard restart.

## Activation result

The verified artifact was copied beside each live binary, checked against the
release SHA, atomically renamed, and activated with the then-current legacy
service unit. `ircx.us` was restarted and verified first; `eshmaki.me` was
then restarted and verified. Both units became `active/running`, reported the
expected banner and SHA, restored their configured grants, and re-established
one TCP Mooring connection on port 6900.

The local user `announce.service` disconnected during the intentional local hard
restart, reconnected six seconds later, and resumed watching both repositories.
Before deployment it detected commit `8eaaedb`, announced the commit in `#root`,
and updated the topic. The earlier report that it was not announcing was caused
by the repository having no new committed HEAD while the implementation was
still uncommitted.

## Client and mesh acceptance

WeeChat had two distinct profiles. `ircx` was already configured for the client
certificate; the literal `ircx.us` profile was still using defaults and had
previously logged `not logged in`. Both profiles now explicitly use:

- `/home/kain/.weechat/tls/relay.pem`;
- TLS with verification;
- SASL EXTERNAL, account/nick/username `kain`; and
- autoconnect plus autoreconnect.

The corrected `ircx.us` login logged that it sent one client certificate,
completed SASL `900` and `903`, registered as `kain`, and reported
`SESSION RESUME: certificate-authenticated session restored`. The `ircx` profile
reported the mesh variant of the same restoration. Neither remote attachment
emitted another `MODE #root +Y kain`.

Final out-of-band acceptance held two certificate-authenticated clients open
concurrently, one through each node, without supplying a session token. Both
registered as account/nick `kain` on `0.5.6+8eaaedb`. Each node authored one
channel message and one direct message. All four markers arrived exactly once on
both transports. For each event, both transports carried the same `time` and
`msgid`; no acceptance client received `MODE #root +Y kain`.

One `+Y kain` was visible when the first local attachment reconstructed the cold
process after the planned hard restart. That was the initial grant transition,
not per-login churn: the later WeeChat attachments and both controlled
certificate attachments were silent, and unchanged grant refreshes are covered
by the ReleaseSafe and Helix regressions.
