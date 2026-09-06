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

Beyond the deterministic-simulation suite, Onyx Server is building a dedicated
adversarial **exploit/attack test harness** — protocol fuzzing and abuse-path
regression tests aimed at the parser, authentication, TLS, and admission
surfaces. The direction and coverage plan live in
[`docs/research/exploit-suite-blueprint.md`](docs/research/exploit-suite-blueprint.md)
(a research/planning document, not a statement of current coverage).

## Supported versions

Onyx Server is developed on a rolling basis; fixes land on `main`. The current
source release line is **0.7.0** (`build.zig.zon:18`). The currently verified
production pair (`eshmaki.me` and `ircx.us`) runs the `0.7.0+ae78d490` artifact
under `onyx-server.service`; the public GitHub artifact channel still publishes
`v0.5.6`. These are deliberately separate source, deployed-image, and public-tag
claims. Operators should track `main`, verify the exact image and configuration,
and apply security fixes through the session-preserving `USR2` hot-upgrade. See
[`docs/ops/onyx-server-paths.md`](docs/ops/onyx-server-paths.md) for the current
fleet evidence and rollback boundary.
