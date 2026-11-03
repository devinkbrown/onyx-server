# The module system

SerpentRegistry assembles the daemon command surface at compile time. A separate
per-server runtime owns lifecycle health, reload staging, availability and hook
counters. The [enabled manifest](../../src/daemon/modules/manifest.zig) lists the
12 current modules; [the feature index](../reference/features.md) lists their
commands and detailed references.

## Declarations and compile-time validation

[registry.zig](../../src/daemon/registry.zig) defines `Module`, `CommandSpec`,
`HookBinding`, protocol metadata and stats-provider declarations. It rejects
ambiguous command/alias ownership, duplicate modules and protocol identifiers,
missing required dependencies, conflicts, cycles, invalid stat names and duplicate
stats names/tokens. Dependencies precede dependents; priority and manifest order
break independent ties.

| Declaration | Meaning |
|---|---|
| `id`, `version`, `category`, `priority` | Stable identity, introspection and dependency-order tie breaking. |
| `requires`, `optional_requires`, `conflicts` | Hard/soft ordering edges and incompatible module sets. |
| `commands`, `hooks` | Typed dispatch and event subscriptions. |
| `caps`, `chanmodes`, `usermodes`, `numerics`, `isupport` | Declared protocol metadata, checked for collisions. These do not replace the separate live CAP/ISUPPORT inventories. |
| `stats` | Provider metadata and read callbacks; declaration support does not imply a live scrape integration. |
| `config_blocks` | Module-owned config metadata; it does not create arbitrary accepted TOML keys. |
| Lifecycle callbacks | Register/init/ready/deinit and configuration preparation/commit/abort contracts. |

A command declares `name`, `min_params`, `access`, optional `feature`, `handler`,
`aliases`, help/summary metadata and anti-abuse classification. Aliases resolve to
the same spec, so they share the canonical arity, access and feature gates.
`MODLIST` is an alias of `MODULES`. `oper_privilege` metadata does not replace the
handler's privilege check. `warden_class` remains declarative: current daemon
flood weighting does not call `Registry.wardenClassFor`.

## Live runtime ownership

[module_runtime.zig](../../src/daemon/module_runtime.zig) exposes `Runtime(mods)`
as an instance with independent health rows, `Bus.Instance`, online state and
configuration generation. Two server instances do not share those arrays. The
older pure lifecycle helper in `module_lifecycle.zig` is useful for its own
harness; it is not the live server's process-global health owner.

`LinuxServer.ensureModuleRuntime` starts register, init and ready phases before
command admission. Required-module failure stops startup and tears down initialized
resources. Optional failures and dependent blocking remove those modules from
availability; healthy modules can proceed. Shutdown runs teardown in reverse
dependency order. Source: `Runtime.start`, `drivePhase`, `stop` and server startup.

All registered daemon commands use `module_runtime.dispatch`, which combines
module availability with access, feature and arity checks. `COMMANDS` lists only
commands available to the caller; `COMMANDS <name>` gives one spec's metadata.
A disabled or unavailable command cannot bypass its gate by using an alias.

## Hooks and fail-closed approval

[module_bus.zig](../../src/daemon/module_bus.zig) groups subscriptions by typed
`HookId`. The live daemon calls `module_runtime.emit(.client_registered, ...)`
for informational registration and `module_runtime.approve(.message_pre_deliver, ...)`
for message approval.

| Operation | Handler failure | Ordering and authority |
|---|---|---|
| `emit` | Counted; other eligible informational delivery can continue. | Informational notification, with runtime availability gates. |
| `approve` | Denies the event. | First denial is final; a later subscriber cannot resurrect it. Wrong non-veto hook types fail at compile time. |

The previous description of a live fail-open `Registry.callHook` message path is
obsolete. The current `validateMessageText` path checks the runtime approval result
before allowing delivery. Hook counters are observability, not authorization;
relaxed atomic reads are not a transactional snapshot.

## Configuration reload

The World mutation lane serializes live command/hook policy and REHASH staging.
`prepareModuleReload` prepares a candidate with a strictly advancing generation.
`Runtime.prepareReload`, `commitReload` and `abortReload` provide the corresponding
module transaction. Failed preparation must abort prepared callbacks and preserve
the active configuration; successful publication advances the live generation.
This lane does not itself pause all socket/background owners, so their separate
ownership and reload contracts still apply.

Module health belongs to the new runtime after Helix; it is not copied as stale
process health. Adopted policy is validated separately before publication.
Use the actual [config parser](../../src/daemon/config_format.zig) and
[boot projection](../../src/daemon/config_boot.zig) to determine accepted sections.

## Introspection and metrics

`MODULES [id]` is operator-only and reports dependency order, state, availability,
configuration generation, declared surfaces, reload/rollback counters and last
failure. `OROWASM STATUS|ABI|WIT|PLUGINS` inspects the separate plugin host.
Source: [introspect.zig](../../src/daemon/modules/introspect.zig).

The metrics renderer exports runtime degradation/configuration-generation and
hook-error/unavailable counters. The separate `Module.stats` provider table remains
empty in the enabled manifest, and is not the current daemon scrape path; see the
[stats-provider contract](../features/STATS-MODULES-UPGRADE.md).

## Development and verification

Declare a bounded module under `src/daemon/modules/`, add it to the manifest, and
add explicit test references so its test blocks are discovered. Runtime integration
must preserve the server's lock and lifecycle boundaries. The integrator owns
`server.zig` changes. [module_harness.zig](../../src/daemon/module_harness.zig),
`module_runtime.zig` and `module_bus.zig` cover ordering, required/optional startup
failure, isolation, reload rollback, availability and veto behavior.

Use [the testing guide](../guide/testing.md) for focused module/server checks and
full ship gates. A registry compile success proves static declarations; it does
not prove a callback's runtime effects or a new external capability's interoperability.
