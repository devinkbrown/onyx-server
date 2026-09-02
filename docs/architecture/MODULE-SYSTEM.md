# The module system

_SerpentRegistry: comptime module assembly and validation, dependency-ordered load, gated command dispatch, the typed module bus, the lifecycle driver, and `MODULES` introspection._

This document covers how a daemon feature is packaged as a module, what the compiler proves about the module set before the binary exists, and what drives a module through its lifecycle at runtime. Local world state and the two-layer dispatch model are covered in [02-world-dispatch-modules.md](02-world-dispatch-modules.md); the Event Spine's typed oper/observer events are a separate system, see [event-spine.md](event-spine.md).

## Why the registry is comptime

The entire module set is assembled, validated, and flattened into static tables at compile time. There is no runtime module loader, no dynamic registration order, and no "module failed to register" boot path to reason about. A module set that would be ambiguous — two modules claiming `KICK`, a missing dependency, a dependency cycle, an alias shadowing another module's command — is a `@compileError`, not a startup failure.

The manifest is the single list. Adding a module is one line; deleting the line dead-code-eliminates it. Evidence: `src/daemon/modules/manifest.zig:27`, `src/daemon/modules/manifest.zig:45`.

Referencing `module_manifest.Live` from the server is what forces validation to run at build time. The eval branch quota is raised there because validation is O(commands²) across the full command surface. Evidence: `src/daemon/modules/manifest.zig:45`, `src/daemon/modules/manifest.zig:46`.

## What a module declares

A `Module` is a plain comptime struct. Every field defaults to empty, so a module declares only the surface it actually contributes. Evidence: `src/daemon/registry.zig:520`.

| Field | Meaning | Evidence |
| --- | --- | --- |
| `id` | Unique module identifier, dotted (`core.ircx`, `diag.introspect`). | `src/daemon/registry.zig:521` |
| `version` | `major.minor.patch`, surfaced by `MODULES`. | `src/daemon/registry.zig:492`, `src/daemon/registry.zig:522` |
| `category` | `core`/`protocol`/`service`/`security`/`feature`/`media`/`diagnostic`. | `src/daemon/registry.zig:499` |
| `priority` | `first`/`early`/`normal`/`late`/`last` — orders modules that have no dependency edge between them. | `src/daemon/registry.zig:510` |
| `requires` | Hard dependencies. A missing one is a compile error. | `src/daemon/registry.zig:526` |
| `optional_requires` | Soft edges: honoured for ordering when present, absent is fine. | `src/daemon/registry.zig:527` |
| `conflicts` | Modules that must not be enabled alongside this one. | `src/daemon/registry.zig:528` |
| `config_blocks` | `[modules.*]` TOML sections this module owns. | `src/daemon/registry.zig:529` |
| `commands` | `CommandSpec` rows — the dispatch surface. | `src/daemon/registry.zig:382`, `src/daemon/registry.zig:531` |
| `hooks` | `HookBinding` subscriptions to typed events. | `src/daemon/registry.zig:455`, `src/daemon/registry.zig:532` |
| `caps`, `chanmodes`, `usermodes`, `numerics`, `isupport` | Protocol surface, uniqueness-checked across the whole set. | `src/daemon/registry.zig:533`–`src/daemon/registry.zig:537` |
| `stats` | Counters and gauges contributed to `/STATS` and Prometheus. | `src/daemon/registry.zig:541` |
| `on_register` … `on_deinit` | Lifecycle phases. | `src/daemon/registry.zig:562`–`src/daemon/registry.zig:572` |

### CommandSpec

A command is declared, not registered. The spec carries everything dispatch and introspection need, so the gate and the help text can never drift from the handler they describe. Evidence: `src/daemon/registry.zig:382`.

| Field | Role | Evidence |
| --- | --- | --- |
| `name`, `min_params`, `handler` | Identity, arity floor, implementation. | `src/daemon/registry.zig:383`, `src/daemon/registry.zig:384`, `src/daemon/registry.zig:426` |
| `access` | Minimum client authority, enforced by the dispatcher *before* the handler runs. | `src/daemon/registry.zig:51`, `src/daemon/registry.zig:387` |
| `feature` | Config feature toggle; a disabled feature makes the command unavailable. | `src/daemon/registry.zig:391` |
| `summary`, `category` | One-line description and grouping for `COMMANDS`. | `src/daemon/registry.zig:393`, `src/daemon/registry.zig:395` |
| `oper_privilege` | Documents which oper privilege the handler enforces internally. Documentation only — the handler stays the sole authority. | `src/daemon/registry.zig:405` |
| `aliases` | Alternate spellings resolving to this same spec. | `src/daemon/registry.zig:415` |
| `help_long` | Multi-line help body, `\n`-separated, one numeric per line. | `src/daemon/registry.zig:419` |
| `warden_class` | Declared anti-abuse cost class. | `src/daemon/registry.zig:421` |
| `deprecated_by` | Names the replacement verb; dispatch is unaffected. | `src/daemon/registry.zig:425` |

**Aliases share one spec.** An alias is not a second row with its own access level — it resolves to the canonical `CommandSpec`, so its gate, arity, feature toggle, and handler are the canonical ones by construction. An alias therefore cannot become a privilege side-door around the real verb. Aliases are hidden from the `COMMANDS` list form and are resolved by `lookupCommand`. Evidence: `src/daemon/registry.zig:415`, `src/daemon/registry.zig:888`, `src/daemon/registry.zig:896`.

`MODLIST` is the worked example: it used to be a duplicate `CommandSpec` pointing at the same handler, which meant the two rows could silently drift apart. It is now an alias. Evidence: `src/daemon/modules/introspect.zig:328`.

**`warden_class` is declarative today.** `WardenClass` maps a command to an anti-abuse cost class — `free` for keep-alives that must never be throttled, `normal` for ordinary verbs, `messaging` for fan-out, `channel_churn` for membership mutation. `Registry.wardenClassFor` resolves it through aliases and returns `null` for a verb the registry does not own, so a caller that gets `null` must fall back to its own default weight rather than treating the command as free. No `flood_guard` call site consumes it yet; wiring it is the follow-up described in [Not yet wired](#not-yet-wired). Evidence: `src/daemon/registry.zig:365`, `src/daemon/registry.zig:906`.

## What the compiler proves

`validate` runs over the module set and returns a `ValidationError` that `Registry` turns into a `@compileError`. Evidence: `src/daemon/registry.zig:576`, `src/daemon/registry.zig:624`, `src/daemon/registry.zig:972`.

| Check | Rejected because | Evidence |
| --- | --- | --- |
| `duplicate_module` | Two modules share an `id`. | `src/daemon/registry.zig:975` |
| `missing_dependency` | A `requires` entry names a module not in the set. | `src/daemon/registry.zig:976` |
| `module_conflict` | Two mutually-exclusive modules are both enabled. | `src/daemon/registry.zig:977` |
| `dependency_cycle` | `requires` edges form a cycle, so no load order exists. | `src/daemon/registry.zig:978` |
| `duplicate_command` | Two modules claim the same verb. | `src/daemon/registry.zig:979` |
| `duplicate_alias` | An alias collides with a canonical command or another alias, case-insensitively. | `src/daemon/registry.zig:973` |
| `duplicate_cap` / `duplicate_channel_mode` / `duplicate_user_mode` / `duplicate_numeric` / `duplicate_stat` | Protocol surface collision. | `src/daemon/registry.zig:980`–`src/daemon/registry.zig:984` |

Command and alias comparison is case-insensitive, matching IRC verb semantics: `MODLIST` and `modlist` are the same command, so declaring both is a collision rather than two commands.

## Dependency-ordered load

`loadOrder` is a comptime topological sort producing a permutation of manifest indices. Evidence: `src/daemon/registry.zig:788`, `src/daemon/registry.zig:884`.

Ordering rules, in precedence order:

1. **Dependencies first.** A module never precedes anything in its `requires` (or a present `optional_requires`). This is the hard constraint — a cycle is a compile error rather than an arbitrary tiebreak.
2. **Then `priority`.** Among modules whose dependencies are all satisfied, lower `Priority` wins: `first` before `early` before `normal` before `late` before `last`.
3. **Then manifest order.** A stable, human-controlled final tiebreak, so the sequence is deterministic across builds.

A dependency edge outranks priority: a `late` dependency still loads before its `first` dependent, because loading a dependent without its dependency is incorrect while running it slightly out of priority is merely unexpected.

## Gated dispatch

`dispatchGated` resolves a verb and enforces its declared contract before the handler is entered. Evidence: `src/daemon/registry.zig:915`.

| Outcome | When | Evidence |
| --- | --- | --- |
| `.denied` | The caller does not meet `access`, or the command's `feature` is disabled. | `src/daemon/registry.zig:79`, `src/daemon/registry.zig:449` |
| `.too_few_params` | Fewer parameters than `min_params`. | `src/daemon/registry.zig:79` |
| `.not_found` | No canonical command or alias matches. | `src/daemon/registry.zig:86` |
| handled | Everything checked; the handler ran. | `src/daemon/registry.zig:86` |

Access and arity are enforced centrally, so a handler is only ever entered with its declared preconditions already true. Per-command privilege checks beyond `access` remain the handler's own responsibility — `oper_privilege` documents them, it does not enforce them.

Lookup goes through a comptime `StaticStringMap` covering canonical names *and* aliases, so alias resolution costs the same as a canonical hit. Evidence: `src/daemon/registry.zig:888`.

## The module bus

`module_bus.Bus` is the typed event spine between modules: a module emits an event, subscribers see it in priority order, and no emitter needs to know who is listening. Evidence: `src/daemon/module_bus.zig:61`.

Bindings are partitioned per `HookId` at comptime, so emitting an event iterates only that event's subscribers rather than filtering the whole hook table at runtime. Evidence: `src/daemon/module_bus.zig:69`, `src/daemon/module_bus.zig:199`.

### Two dispatch functions, because errors mean different things

The split is the reason this file exists rather than a single `emit`.

| | `emit` | `approve` |
| --- | --- | --- |
| For | Informational events (`client_registered`, `mesh_peer_up`) | Veto-capable events (`message_pre_deliver`, `nick_pre_change`) |
| Handler error | Counted and swallowed — a broken subscriber must not break the emitting path | **Fails closed**: the event is denied |
| Denial | N/A | First denial wins and dispatch stops |
| Wrong hook kind | — | **Compile error** |
| Evidence | `src/daemon/module_bus.zig:88` | `src/daemon/module_bus.zig:123` |

Passing an informational hook to `approve` is a compile error, because its payload has no `approved` field and the veto would be silently dropped. Evidence: `src/daemon/module_bus.zig:128`, `src/daemon/registry.zig:309`.

**Veto finality.** `approve` returns at the first denial, so a later subscriber can never resurrect a denied event, and a handler that faults is treated as having denied it. Evidence: `src/daemon/module_bus.zig:139`, `src/daemon/module_bus.zig:145`.

This is the behavioural difference from the older `Registry.callHook`, which is still what the live daemon calls. `callHook` propagates a handler error with `try`, aborting the emit and skipping every remaining subscriber. Evidence: `src/daemon/registry.zig:955`, `src/daemon/registry.zig:963`. At the `message_pre_deliver` site the error is caught and mapped to `.continue_`, then `approved` is read. Evidence: `src/daemon/server.zig:50531`, `src/daemon/server.zig:50533`. The consequence is fail-open: a subscriber that faults suppresses every veto that would have come after it, and the message is delivered. `Bus.approve` is the fail-closed replacement; the call sites have not been migrated yet ([Not yet wired](#not-yet-wired)).

Per-hook counters (`emitted`, `vetoed`, `handler_errors`) are relaxed atomics read independently, so a concurrent emit may be reflected in some counters and not others. They are a statistics view and must never be used as a control input. Evidence: `src/daemon/module_bus.zig:43`, `src/daemon/module_bus.zig:154`.

## The lifecycle driver

`module_lifecycle.Lifecycle` drives phases, remembers how each module fared, and makes a configuration reload all-or-nothing. Evidence: `src/daemon/module_lifecycle.zig:160`.

Like `Registry` and `Bus` it is a namespace over process-global state, not a handle: instantiating `Lifecycle(&manifest.enabled)` twice yields the same type and therefore the same health arrays, which is why the server can drive the phases and an introspection module can read the results without a pointer being threaded between them. Evidence: `src/daemon/module_lifecycle.zig:160`, `src/daemon/modules/introspect.zig:25`.

### Phases

| Phase | Driver | Order | Contract |
| --- | --- | --- | --- |
| `register` | `driveRegister` | dependency | Registration-time setup before any other phase. | 
| `init` | `driveInit` | dependency | Startup work, before listeners are armed. |
| `ready` | `driveReady` | dependency | After the server is accepting connections. |
| `reload` | `driveReload` | dependency, with rollback | Re-derive cached policy from the new config. |
| `deinit` | `driveDeinit` | **reverse** dependency | Teardown; cannot fail. |

Evidence: `src/daemon/module_lifecycle.zig:46`, `src/daemon/module_lifecycle.zig:191`, `src/daemon/module_lifecycle.zig:196`, `src/daemon/module_lifecycle.zig:201`, `src/daemon/module_lifecycle.zig:254`, `src/daemon/module_lifecycle.zig:317`.

Startup runs in dependency order so a module never initialises before something it requires; `deinit` runs in the exact reverse so a dependency outlives its dependents.

**A failed phase quarantines the module.** A module whose phase returned an error is recorded `.failed` and skipped by every later phase: its invariants are unknown, so calling further phases on it would operate on state it never finished building. Registration deliberately does not fail the boot — refusing to start the daemon over one optional module's registration is a worse outcome than running without it. Evidence: `src/daemon/module_lifecycle.zig:187`, `src/daemon/module_lifecycle.zig:220`.

### The REHASH contract

A configuration reload is all-or-nothing across modules. If module N's `on_reload` fails, the driver restores the previous configuration through the caller's `RestoreFn` and re-invokes `on_reload` in reverse dependency order across every module that had already accepted it, leaving the daemon wholly on the old configuration rather than half-way between two. Evidence: `src/daemon/module_lifecycle.zig:254`, `src/daemon/module_lifecycle.zig:292`, `src/daemon/module_lifecycle.zig:144`.

This is why **`on_reload` must be idempotent and must re-derive from configuration rather than apply a delta**: the rollback path calls it a second time with the configuration restored, and expects that to reproduce the prior state. Evidence: `src/daemon/module_lifecycle.zig:27`.

Rollback deliberately continues past an error. A module left on the rejected configuration is worse than one that failed to rewind, so every module in the prefix is attempted and the first rewind failure is reported in `Failure.rollback_failed`. A non-null value there means the daemon could not be returned to a known-good state and the operator must restart rather than trust the running configuration. Evidence: `src/daemon/module_lifecycle.zig:248`, `src/daemon/module_lifecycle.zig:136`.

`ReloadOutcome` reports which module refused, its error, how many modules were rewound, whether the restore callback ran, and whether any rewind itself failed. Evidence: `src/daemon/module_lifecycle.zig:108`, `src/daemon/module_lifecycle.zig:125`.

REHASH must never drop or mutate live connections — it is a zero-disconnect operation. Evidence: `src/daemon/registry.zig:570`, `src/daemon/module_lifecycle.zig:253`.

### What cannot hot-reload

`on_reload` re-derives cached policy. It cannot change anything decided before or outside the module set:

- **The module set itself.** Modules are a comptime list; enabling or disabling one is a rebuild, not a REHASH.
- **Any comptime table** — commands, aliases, caps, modes, numerics, ISUPPORT, stats, hook bindings, load order. All are `const` in the binary.
- **Listener sockets and the reactor topology** (`num_shards`), which are established at boot and owned by the reactor, not by a module.
- **Anything a module captured by reference from the old configuration.** A module must value-copy the policy it caches; retaining a borrowed config slice across a REHASH leaves a dangling slice when the old configuration is freed.

### Health

Health is read by `MODULES` from any reactor thread while phases are driven single-threaded (startup and shutdown are pre/post-reactor; REHASH is primary-reactor-gated work). Every health field is therefore an independent relaxed atomic, and `last_error` is stored as an error *code* via `@intFromError` rather than a string, because an integer store is atomic where a `[]const u8` would not be. Evidence: `src/daemon/module_lifecycle.zig:32`, `src/daemon/module_lifecycle.zig:43`, `src/daemon/module_lifecycle.zig:395`.

| `State` | Meaning | Evidence |
| --- | --- | --- |
| `unloaded` | No phase driven yet. | `src/daemon/module_lifecycle.zig:61` |
| `registered` / `initialized` / `ready` | Passed that phase; `ready` is the steady state. | `src/daemon/module_lifecycle.zig:63`, `src/daemon/module_lifecycle.zig:65`, `src/daemon/module_lifecycle.zig:67` |
| `failed` | A phase returned an error; `failed_phase` says which. | `src/daemon/module_lifecycle.zig:69` |
| `stopped` | Torn down. | `src/daemon/module_lifecycle.zig:71` |

`last_error` is deliberately **not** cleared by a later success, so an operator can still see that a past REHASH was rejected; `state` carries the current verdict. `reload_count` counts successful reloads only — rollback re-invocations are counted separately in `rollback_count` so they cannot inflate it. Evidence: `src/daemon/module_lifecycle.zig:88`, `src/daemon/module_lifecycle.zig:94`.

`positionOf` is a comptime-built inverse of `load_order`, so mapping a manifest index to a load position is a table lookup with no scan and no `unreachable` — `load_order` is a permutation of `0..count` by construction. Evidence: `src/daemon/module_lifecycle.zig:377`, `src/daemon/module_lifecycle.zig:384`.

## MODULES

Oper-gated introspection over the whole system. `MODLIST` is an alias. Evidence: `src/daemon/modules/introspect.zig:52`, `src/daemon/modules/introspect.zig:323`.

`MODULES` with no argument lists every module in dependency-resolved load order with its version, category, priority, runtime state and declared surface size, then a totals line covering modules, commands, aliases, hooks, and degraded count. A module in `.failed` is marked `DEGRADED`. Evidence: `src/daemon/modules/introspect.zig:66`, `src/daemon/modules/introspect.zig:93`.

`MODULES <module-id>` shows one module's dependency edges, optional edges, conflicts, owned config blocks, full declared surface, and its lifecycle counters and last failure. Evidence: `src/daemon/modules/introspect.zig:103`.

The command is gated twice on purpose: `access = .oper` refuses a non-oper at the registry gate and hides the verb from that caller's `COMMANDS` listing, and the handler still checks `isOper()` itself. Evidence: `src/daemon/modules/introspect.zig:324`, `src/daemon/modules/introspect.zig:54`.

When no phase has been driven, every module reads `unloaded`. That is indistinguishable from "every module failed" if you only look at the state column, so `MODULES` emits an explicit note in that case rather than letting an operator misread a cold driver as a mass fault. Evidence: `src/daemon/module_lifecycle.zig:358`, `src/daemon/modules/introspect.zig:89`.

## Test harness

`module_harness.zig` builds synthetic modules whose lifecycle and hook behaviour is scripted by a `Probe`, so load order, REHASH rollback, and bus delivery are tested against a known graph rather than against whatever the real manifest happens to contain today. Evidence: `src/daemon/module_harness.zig:60`, `src/daemon/module_harness.zig:285`.

The `Probe` records an ordered log of observable steps — `register`, `init`, `ready`, `reload`, `rewind`, `deinit`, `hook`, `restore` — and can inject a failure into a named module's phase or hook. It is fixed-capacity and allocation-free, and flags `overflowed` rather than silently truncating a sequence a test is about to assert on. Evidence: `src/daemon/module_harness.zig:36`, `src/daemon/module_harness.zig:60`.

Distinguishing `reload` from `rewind` is what makes the rollback tests meaningful: both call the same `on_reload` handler, and only the probe's `in_rollback` flag tells them apart in the log. Evidence: `src/daemon/module_harness.zig:53`.

Covered scenarios: dependency-ordered phases with reverse-ordered teardown; an `on_init` failure quarantining one module while the others proceed; a clean REHASH; a failed REHASH rolling back LIFO with config restore; a rollback that itself fails being reported without aborting the remaining rewinds; a REHASH with no restore hook reporting `restore_invoked=false`; informational bus delivery honouring priority and counting errors; veto finality and fail-closed handler errors on `approve`; and an empty subscriber set. Evidence: `src/daemon/module_harness.zig:316`, `src/daemon/module_harness.zig:368`, `src/daemon/module_harness.zig:414`, `src/daemon/module_harness.zig:546`, `src/daemon/module_harness.zig:592`, `src/daemon/module_harness.zig:617`.

## Not yet wired

The pieces below are implemented and tested but are not on the live daemon path. They are listed here so the gap is explicit rather than discovered.

| Gap | Current live behaviour | What adoption requires |
| --- | --- | --- |
| Lifecycle driver | `server.zig` has its own inline walk that drives `on_init`/`on_ready` in **manifest** order, drives `on_deinit` in manifest order too, never calls `on_register` or `on_reload`, and records no health — so `MODULES` reports `unloaded`. Evidence: `src/daemon/server.zig:14424`, `src/daemon/server.zig:14437`. | Replace the body of `driveLifecycle`/`driveDeinit` with `Lifecycle.driveInit`/`driveReady`/`driveDeinit`, add `driveRegister` at boot, and call `driveReload` from the REHASH path with a `RestoreFn`. |
| Module bus | Hook emission still goes through `Registry.callHook`, which aborts the chain on a handler error and is fail-open at the veto site. Evidence: `src/daemon/server.zig:14450`, `src/daemon/server.zig:50531`. | Route informational hooks through `Bus.emit` and `message_pre_deliver`/`nick_pre_change` through `Bus.approve`. The compile-time check on `approve` prevents mixing the two up. |
| `warden_class` | No `flood_guard` call site consumes it; command weighting is unchanged. | Have the flood-guard weight lookup consult `Live.wardenClassFor(verb)` and fall back to its existing default on `null`. |
| `config_blocks` | Declared and validated, but `[modules.*]` TOML sections are not yet routed to the owning module. | Route each parsed `[modules.<name>]` section to the module declaring it in `config_blocks`, and fail closed on a section no module owns. |

Each of these is a `server.zig` edit, which is why they are staged separately from the module-side work.
