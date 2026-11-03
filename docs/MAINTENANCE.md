# Documentation maintenance

Documentation is part of the public interface. A command, configuration field,
capability or upgrade rule is documented where a reader can find its supported
behavior, activation conditions, limits and a usable example. A source symbol
or parsed field alone is not evidence that a feature is enabled or accepted.

## One authoritative home per topic

| Information | Authoritative document | Update trigger |
|---|---|---|
| Product introduction and first build | [README](../README.md) | Entry points, baseline compiler or major public scope changes. |
| Public feature inventory | [Feature reference](reference/features.md) | Commands, capabilities, configuration families or platform behavior change. |
| Configuration semantics | [Config reference](reference/config.md) | A parser/default/projection/consumer changes. |
| Runnable configuration example | [Reference TOML](../etc/onyx-server.reference.toml) | Keep examples consistent with active parsing and required relationships. |
| Wire syntax and policy | [Command index](reference/commands/_index.md), [protocol references](reference/ircv3.md) | New/changed command, capability, mode, numeric, limit or failure. |
| Implementation ownership and invariants | [Architecture](architecture/00-overview.md), [source map](architecture/source-modules.md) | Module boundary, transaction, concurrency, transport or carry format changes. |
| Development and verification | [Development](development.md), [testing](guide/testing.md) | Toolchain, test graph, failure workflow or evidence rules change. |
| Deployment procedure | [Runbook](RUNBOOK.md), [service kits](guide/service-management.md) | Startup/reload/stop, staging, privilege or rollback behavior changes. |
| Running production identity | [Production status](ops/onyx-server-paths.md) | Accepted deployment changes image, manager, path or configuration. |
| Release changes and evidence | [NEWS](../NEWS.md), [latest evidence](audit/README.md) | Accepted behavior, measured result or deployment. |

The [docs hub](README.md) is navigation, not another copy of these contracts.
Small task indices may link to a page; they must not repeat its full procedure.
Link volatile deployment hashes and service details to the production page
instead of copying them into skills, guides and feature descriptions.

## What a detailed feature page contains

For each public behavior, document:

1. **Purpose and entry point.** The client command, CLI option, config key,
   capability or API, and who is permitted to use it.
2. **Activation.** Defaults, prerequisites, related settings, supported platforms,
   capability negotiation and whether restart or reload is required.
3. **Semantics.** State ownership, ordering, persistence, visibility, identity
   and policy decisions. Distinguish a local attachment from a logical session.
4. **Limits and failure.** Sizes/units, bounds, rejection, retry, replay,
   cancellation and cleanup. Say when an operation is refused transactionally.
5. **Examples.** A minimal happy path, meaningful rejection or recovery example,
   expected observable result and links to related commands/settings.
6. **Implementation and verification.** Stable file/symbol links, relevant test
   lanes, and the scope of any native or deployed evidence.

A short index entry can link a detailed existing page instead of duplicating
these sections. New documentation does not make a proposal implemented, an
optional feature enabled, or a cross build a native runtime acceptance.

## Example conventions

- State the context: shell vs IRC wire text vs TOML, evaluation vs production,
  platform, working directory, privileges and required secrets.
- Use reserved example hostnames and placeholder secrets. Do not include live
  keys, reusable credentials, private acceptance state or generated account data.
- Explain relative paths. The automatically generated node identity key is
  beside the selected config; relative account/state paths may use the process
  working directory. An installed service can have a different working directory
  from an interactive shell.
- Keep optional configuration examples disabled unless the example is explicitly
  demonstrating their activation. Describe required accompanying fields.
- Match the pinned compiler's actual flag spelling. Use `-Doptimize=safe` for
  safety-checked tests and the documented `release`/`--release=fast` build paths.
- Show observable results, not invented output transcripts. A reload signal is
  not an acknowledgement that a successor adopted. An exit code without counts
  is not a complete test gate.
- Prefer stable file/symbol references over absolute line numbers that drift
  during normal edits. Link a Git revision when the claim concerns old bytes.

## Audit all repository text

Run from the repository root:

```sh
python3 -B tools/check_docs.py
python3 -B tools/test_check_docs.py
python3 -B tools/check_docs.py --inventory-json .zig-cache/documentation-inventory.json
```

The checker inventories repository-owned text and validates local Markdown
links/anchors plus obsolete optimization spellings in current documentation.
It excludes ignored/generated/private files and does not fetch every external
URL. It does not prove prose semantics, runtime support or legal/security claims;
those need source review and relevant evidence.

A complete review includes README/NEWS, guides, architecture, configuration and
protocol references, agent instructions, package comments, MOTD/news examples,
CLI help and build/CI instructions. Preserve frozen protocol/domain literals,
third-party normative excerpts, copyright notices and test vectors. A product
rename must not change authenticated wire domains or legacy compatibility inputs.

When changing agent/toolkit instructions, also run:

```sh
python3 -B .agents/skills/onyx-server-agent-toolkit/scripts/validate_toolkit.py
```

Use the [roster](../.agents/ROSTER.md) for file authority and a fresh reviewer for
release-critical claims. Documentation checks can run without recompiling the
full Zig suite. Reuse unchanged source-bound accepted evidence; use focused
checks for an example/tool change instead of automatically rerunning every
long release gate.

## Retired documents

Obsolete 0.7 plans, overlapping speculative catalogs, completed port diaries,
old release-preparation pages and historical audit packets have been removed
from this working tree. Their original contents remain in Git history at
[`3fa6e95021601c92d2a2b68869d8fa9f4047d391`](https://github.com/devinkbrown/onyx-server/tree/3fa6e95021601c92d2a2b68869d8fa9f4047d391/docs).
For example, inspect a former page without restoring obsolete instructions:

```sh
git show 3fa6e95021601c92d2a2b68869d8fa9f4047d391:docs/FEATURE-ROADMAP.md
```

Current links must point to current replacements. A dated historical assertion
that still needs its original proof should use an exact Git blob link, not a
missing local file. Keep NEWS history scoped to its release date. Do not convert
old pass counts or proposal checklists into current acceptance claims.

Requirements that remain open are not obsolete merely because their planning
date is old. The [integrated baseline](ROADMAP-2026-10-26.md),
[acceptance ledger](ops/roadmap-acceptance-ledger-2026-10-26.md), and proposed
client integration contracts retain their explicit acceptance boundaries.

Retirement never authorizes deleting unrelated untracked user evidence or
runtime files. Remove only identified repository documents and update their
inbound links. The documentation inventory and Git diff make that scope
reviewable before publication.
