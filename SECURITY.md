# Security Policy

Onyx Server is a network daemon with its own TLS stack, post-quantum server-to-server
cryptography, and authentication surface. We take security reports seriously.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/devinkbrown/onyx-server/security/advisories/new)
("Report a vulnerability" under the repository's **Security** tab). If that is
unavailable, email **devin.kyle.brown@gmail.com** with the details.

Please include:

- A description of the issue and its impact.
- Steps to reproduce, or a proof of concept.
- The affected version (commit hash) and your configuration, with secrets redacted.

We aim to acknowledge a report within a few days and to keep you updated as we
investigate and prepare a fix. Please give us a reasonable window to release a fix
before any public disclosure, and coordinate timing with us.

## Scope

High-interest areas include:

- The TLS 1.3 / hardened TLS 1.2 stack and certificate handling. The TLS 1.2
  profile requires Extended Master Secret (RFC 7627) by default, and the TLS 1.3
  server pins the HelloRetryRequest cipher suite, validates the retried
  `key_share` group, enforces a 0-RTT ticket-age freshness window, and is
  fail-closed across the handshake state machine.
- The Mooring handshake and Undertow mesh record layer (server-to-server crypto).
- Authentication: SASL (PLAIN / SCRAM / EXTERNAL), session tokens, CERTFP.
- Host cloaking: the Argon2id-derived cloak key and the epoch-rotated anonymous
  cloaks (`[cloak] anon_epoch_secs`).
- Connection admission, flood/raid controls, `WARD` enforcement, and resource bounds.
- The in-place upgrade (Helix) state handoff and the WASM plugin host.

## Adversarial testing

The deterministic simulation suite is supplemented by `zig build test-exploit`
(and its `test-attack` alias), plus bounded parser corpus replay through
`zig build fuzz`. Inspect the selected tests and assertions before claiming a
particular vulnerability class is covered. Historical coverage planning lives in
[`docs/research/exploit-suite-blueprint.md`](https://github.com/devinkbrown/onyx-server/blob/3fa6e95021601c92d2a2b68869d8fa9f4047d391/docs/research/exploit-suite-blueprint.md)
(a research/planning document, not a statement of current coverage).

## Supported versions

Onyx Server is developed on a rolling basis; fixes land on `main`. The source
release line is **0.9.0** (`build.zig.zon`). A source version, a public release tag
and a deployed artifact are separate facts. Include the exact affected revision
when reporting an issue or assessing whether a fix is present.

Operators should verify the exact artifact revision, configuration and release
evidence before applying fixes. Prefer session-preserving Helix USR2 when the
image capabilities and live state allow it; otherwise follow the documented
cold-restart and durable-token recovery procedure. See the dated
[production paths and artifact receipt](docs/ops/onyx-server-paths.md) and
[release workflow](docs/RUNBOOK.md).
