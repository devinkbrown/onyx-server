# Developing Onyx Server

This guide connects source ownership, implementation work, testing and release
acceptance. It describes the current repository. Proposals and old execution
logs are indexed separately in the [archive](MAINTENANCE.md#retired-documents) and
[developer history](dev/README.md).

## Set up a reproducible workspace

1. Read [AGENTS.md](../AGENTS.md) for repository boundaries and production
   invariants, and [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution policy.
2. Install the pinned compiler in the [build guide](guide/build.md). Record
   `zig version`, the compiler hash, target and optimization mode with evidence.
   The accepted Linux release used Zig 0.17.0; the current spellings are
   `-Doptimize=safe` and `--release=fast`.
3. Run `zig build check`, then the narrow test lane for the component you will
   change. Existing failures need diagnosis before a broad rerun.
4. Keep temporary runtimes, keys, test accounts and build outputs out of tracked
   source. Use an isolated writable runtime directory and explicit test config;
   launching the daemon without one can bind its default listeners.

A clean source commit binds a production artifact to its embedded revision.
Test binaries intentionally use stable `+test` metadata so a documentation
commit does not force an expensive rebuild. The test receipt still binds the
real source inputs and binary hashes; a test stamp is not release provenance.

## Source and ownership map

| Area | Entry points | Responsibility |
|---|---|---|
| Build graph and package version | [build.zig](../build.zig), [build.zig.zon](../build.zig.zon) | Artifacts, test roots, focused/cached/full gates, target/mode policy and source version. |
| Executable lifecycle | [main.zig](../src/main.zig), [CLI modules](../src/cli) | Argument dispatch, setup/doctor/offline modes, config preflight, listener and service startup. |
| Live daemon integration | [server.zig](../src/daemon/server.zig) | Reactor lifecycle, accepted-event transactions, physical clients, mesh, persistence and upgrade integration. This file has one designated integrator writer. |
| Commands and modules | [dispatch.zig](../src/daemon/dispatch.zig), [registry.zig](../src/daemon/registry.zig), [module manifest](../src/daemon/modules/manifest.zig) | Registration, command metadata, authorization/dispatch and module-owned handlers. |
| Configuration | [config_format.zig](../src/daemon/config_format.zig), [reference TOML](../etc/onyx-server.reference.toml) | Typed defaults, parsing, bounds, environment/file indirection and runtime projection. |
| Wire contracts | [protocol modules](../src/proto), [capability metadata](../src/proto/live_cap_metadata.zig) | IRC/IRCX framing, negotiated features, strict codecs, stable signed transcripts. |
| Cryptography | [crypto modules](../src/crypto), [crypto architecture](architecture/crypto.md) | Armor TLS, Mooring primitives, secret handling, certificates and authenticated encryption. |
| Substrate | [substrate modules](../src/substrate), [reactor architecture](architecture/01-reactor-threading.md) | Data structures, clocks, simulation and platform support. The production Linux Ringlane backend lives under `src/daemon`, not the substrate ring prototype. |
| Operations and delivery | [packaging](../packaging), [tools](../tools), [service kits](guide/service-management.md) | Build/reproduction, runtime smokes, service supervision, health and release procedures. |

Use the [source-module map](architecture/source-modules.md) before adding a new
facade or helper. Shared types belong with their canonical owner; an alias in a
facade should not become an independent implementation.

## Implementing a feature

### Establish the contract

Start from a concrete observable behavior and its failure cases. Identify the
public command, config key, capability, wire object, persistence record or CLI
entry point involved. Look in the [feature index](reference/features.md) before
adding something that already exists behind another public surface.

Write down authorization, limits, retry semantics, lifetime and cleanup. Decide
whether a setting is startup-only, reloadable, carried across Helix, durable
across cold restart, or only local to the process. A parsed field without a
runtime consumer is not a completed feature.

### Add or change an IRC command

- Locate its declaring module and the registry/dispatch metadata. Preserve
  command case rules, registration requirements, privilege checks and bounds.
- Keep `NOTICE` error behavior distinct from `PRIVMSG`: it must not create error
  reply loops. Use the established numerics and structured failure paths.
- For mesh-visible mutation, determine whether it is signed-origin state,
  accepted MESSAGE_V2 delivery, or a terminal legacy compatibility operation.
  Do not introduce an unsigned or non-retained fallback on a required v2 path.
- Update the [command reference](reference/commands/_index.md), relevant
  capability/ISUPPORT entries and [feature index](reference/features.md).
- Verify actual clients observe the result, including remote recipients and
  sibling attachments where applicable. A handler-only unit test does not prove
  delivery through the live server.

### Add or change configuration

Update the typed default/parser, bounds, runtime projection and annotated TOML
example together. Check whether setup, doctor, `--check-config`, reload and
platform-specific service startup use the same interpretation. Invalid explicit
configuration must fail rather than silently selecting a different identity.

Document units, defaults, maximums, secret indirection, relative path base,
activation/restart requirements and platform restrictions in the
[configuration reference](reference/config.md). Keep secrets out of diagnostics
and generated plans. Test both the accepted value and the rejection boundary.

### Change persistence, mesh or Helix

These changes require explicit transaction and compatibility reasoning:

| Invariant | What to demonstrate |
|---|---|
| Prepare before publish | Every allocation, validation and durable preparation that can fail occurs before the accepted mutation becomes visible. |
| Retry safety | A failed attempt leaves replay identity, slowmode state, history, outbox and attachment state available for a correct retry. |
| Immutable origin | Forward the byte-identical signed-origin object; never regenerate origin identity, message ID, timestamp or signed fields at a relay. |
| Physical attachment identity | Preserve every live socket/attachment relation instead of selecting a single representative of a reusable logical session. |
| Strict adopt | Missing or malformed mandatory carried state aborts the successor transactionally; legacy decode is confined to explicit cold migration. |
| Resource ownership | Workers, buffers, file descriptors, timers and queues have clear owners; cancellation and cleanup complete before state is freed. |
| Compatibility | Capability/capsule changes are checked before exec/handoff. A refused upgrade leaves the predecessor usable. |

Use the [session contract](design/session-resume-anywhere-blueprint.md),
[MESSAGE_V2 transaction](design/message-v2-exact-once.md),
[mesh security](architecture/mesh-security.md), and
[upgrade architecture](architecture/04-upgrade-wasm.md) as the detailed contracts.
Do not infer cold durability from successful Helix carry, or platform-native
acceptance from successful cross compilation.

## Verification without repeated long waits

The [testing guide](guide/testing.md) is authoritative for target names and
selection behavior. A productive sequence is:

1. Compile the smallest affected leaf or filtered module while implementing.
2. When exploring several cases in the same root, use `test-cached` or
   `test-exe-cached` and runtime `--test-filter`; later filters reuse the binary.
3. Run affected caller/integration gates, including ReleaseSafe for critical
   session, mesh, crypto, persistence and upgrade behavior.
4. Sweep allocation failures until the first normal success after the last
   injected failure. Assert rollback, cleanup and retry, not just an error code.
5. Use deterministic schedules/seeds for fault campaigns. A topology test needs
   distinct nodes, secured links, actual transports and nonzero exact deliveries.
6. At release, use the complete Debug deterministic gate and required Safe
   coverage, artifact reproduction and a fresh independent reviewer. Check the
   actual test counts, skip identities, source/log hashes and terminal cleanup.

Do not schedule overlapping broad gates merely because their names differ. A
successful unchanged source-bound gate may be reused after independent review;
a changed dependency or unresolved failure justifies rerunning it. The full
native POSIX runner proves disjoint exhaustive inventories before sharding and
fails on test/process errors, leaks, logged errors, timeouts or malformed counts.
Advisory duration profiles change scheduling only; they cannot grant acceptance.

## Review and release

Reviewers should try to refute the behavior, particularly authorization,
rollback, races, replica convergence and cleanup. Writers do not grade their
own release-critical changes. The [agent roster](../.agents/ROSTER.md) defines
file authority and bounded delegation; [agent workflow](dev/agent-workflow.md)
explains its use. No two writers own `server.zig` concurrently.

The [runbook](RUNBOOK.md) owns build/staging/rollback procedures. The
[production paths page](ops/onyx-server-paths.md) owns live identity and service
facts. Deployment needs explicit authorization, a verified artifact and rollback
capture, then one-node-at-a-time activation and mesh/client acceptance. Publish
the GitHub result after acceptance. A docs commit does not require replacing an
unchanged accepted production daemon.

Every public feature change also updates its authoritative reference, feature
index and [NEWS](../NEWS.md). Follow [documentation maintenance](MAINTENANCE.md)
to keep examples, links and historical status consistent.
