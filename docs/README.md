# Onyx Server documentation

Use the task index below to reach the current contract. The source manifest is
**0.9.0**; the accepted November 3 deployment and its exact artifact/service
identity live in [production status](ops/onyx-server-paths.md). Source, running
image, public release tag and proposed work are separate facts.

## Start with your task

| Task | Start here | Detailed reference |
|---|---|---|
| Understand what the server supports | [Feature index](reference/features.md) | [Commands](reference/commands/_index.md), [configuration](reference/config.md), [capabilities](reference/protocol/caps.md) |
| Run a first node | [Quickstart](guide/00-quickstart.md) | [Build](guide/build.md), [setup plans](guide/setup.md), [guide index](guide/README.md) |
| Operate a public service | [Runbook](RUNBOOK.md) | [Service kits](guide/service-management.md), [TLS](guide/tls.md), [operator guide](guide/operators.md) |
| Link nodes or investigate disconnects | [Mesh guide](guide/mesh.md) | [Disconnect diagnosis](ops/client-disconnects.md), [diagnostics](guide/diagnostics.md), [operations index](ops/README.md) |
| Configure accounts, history or media | [Feature index](reference/features.md) | [Account commands](reference/commands/accounts-services.md), [messaging](reference/commands/messaging.md), [media](architecture/03-media.md) |
| Develop or review a change | [Development guide](development.md) | [Source map](architecture/source-modules.md), [testing](guide/testing.md), [contributing](../CONTRIBUTING.md) |
| Understand architecture and invariants | [Architecture overview](architecture/00-overview.md) | [Mesh security](architecture/mesh-security.md), [credentials](reference/credential-domains.md), [Helix](architecture/04-upgrade-wasm.md) |
| Package or verify a release | [Packaging](../packaging/README.md) | [Runbook](RUNBOOK.md), [release verification](audit/release-and-test-speed-2026-11-03.md) |
| Maintain these documents | [Maintenance rules](MAINTENANCE.md) | `python3 -B tools/check_docs.py` |

## Public contracts

The [feature index](reference/features.md) groups supported surfaces and points
to their behavior, controls, limits and source owners. The detailed references
are authoritative for syntax and policy:

- [IRC command index](reference/commands/_index.md), [IRCv3 profile](reference/ircv3.md)
  and [IRCX reference](reference/ircx/README.md).
- [Host command line](reference/server-cli.md) and [Armor toolkit](reference/armor-cli.md).
- [Configuration](reference/config.md) and the
  [annotated TOML](../etc/onyx-server.reference.toml).
- [Modes](reference/protocol/modes.md), [numerics](reference/protocol/numerics.md),
  [ISUPPORT](reference/protocol/isupport.md) and [capabilities](reference/protocol/caps.md).
- [Credential domains](reference/credential-domains.md),
  [host cloaking](reference/host-cloaking.md), [Web Push](reference/web-push.md)
  and [native media authentication](reference/native-media-mac.md).
- [Reusable sessions](design/session-resume-anywhere-blueprint.md),
  [MESSAGE_V2 exact-once transaction](design/message-v2-exact-once.md), and
  [Event Spine v2](design/event-spine-mesh-v2.md).

The [glossary](reference/glossary.md) maps Undertow, Mooring, Armor, Helix,
Ringlane and the other subsystem names to source.

## Status, evidence and proposed work

Read [NEWS](../NEWS.md) for changes and
[production status](ops/onyx-server-paths.md) for the accepted running fleet.
The [latest release/test-speed report](audit/release-and-test-speed-2026-11-03.md)
records counts, timings, reproduction and acceptance limits. Native platform
claims require their own evidence; a compiler pass is not a running-system test.

Dated [audits](audit/README.md), [developer records](dev/README.md), and old
operational reports retain their original evidence. Obsolete overlapping plans
have been retired from the active tree and are recoverable through the
[archive index](MAINTENANCE.md#retired-documents). Their old versions, counts and TODOs do not
establish current behavior.

The [integrated requirements baseline](ROADMAP-2026-10-26.md),
[acceptance ledger](ops/roadmap-acceptance-ledger-2026-10-26.md), and
[client integration outline](design/onyx-client-integration-2026-10-26.md)
remain scoped planning/acceptance records. Passing this release does not close
every roadmap row or prove changes in the separate client repository.
