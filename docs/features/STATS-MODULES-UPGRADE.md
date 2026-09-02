# Stats provider registry and module metadata

_How a SerpentRegistry module contributes a counter or gauge to `/STATS` and the
Prometheus endpoint without a hand-written field on `server_stats.Stats`._

## Problem

Before this landed, every exported metric had to be a hand-written field on
`server_stats.Stats` plus a hand-written row in its fixed `rows()` array. A
module could not export a metric of its own; the metric surface only grew by
editing the core stats struct. Evidence: `src/daemon/stats_provider.zig:8`.

## What landed

A module now declares `stats: []const stats_provider.Spec` on its `Module`
struct, and `Registry(mods)` aggregates every module's providers into one flat,
comptime-built table — the same pattern already used for `commands`, `caps`,
`chanmodes`, `usermodes`, `numerics`, and `isupport`.

| Piece | Behavior | Evidence |
| --- | --- | --- |
| `Module.stats` | Per-module list of `stats_provider.Spec` (Prometheus name, short STATS token, HELP text, kind, category, read fn). | `src/daemon/registry.zig:483`, `src/daemon/registry.zig:486` |
| `registry.StatsSpec` / `StatsEntry` / `StatsKind` / `StatsCategory` | Re-exports of `stats_provider.{Spec,Entry,Kind,Category}` so a module declaring `stats:` needs only `registry`, not a second import. | `src/daemon/registry.zig:21`, `src/daemon/registry.zig:22`, `src/daemon/registry.zig:23`, `src/daemon/registry.zig:24`, `src/daemon/registry.zig:25` |
| `ValidationKind.duplicate_stat` | Two modules declared the same Prometheus name or the same short STATS token (case-insensitively for the token). | `src/daemon/registry.zig:527`, `src/daemon/registry.zig:881` |
| `ValidationKind.invalid_stat_name` | A provider's `prom` or `irc` name is not a legal Prometheus metric name / STATS token. | `src/daemon/registry.zig:531` |
| `findPriorStat` | Prior-declaration scan (mirrors `findPriorCommand`/`findPriorCap`) checked against both the `prom` and `irc` namespaces. | `src/daemon/registry.zig:881` |
| `countStats` / `buildStatsTable` | Comptime count + flatten of every module's `stats` into `[N]StatsEntry`, tagged with the declaring module's id, in manifest order. | `src/daemon/registry.zig:1004`, `src/daemon/registry.zig:1010` |
| `Registry(mods).stats` | The built table, exposed the same way as `.commands`/`.caps`/etc. | `src/daemon/registry.zig:720` |
| `validationMessage` | Exhaustive `ValidationKind` switch now covers `duplicate_stat` and `invalid_stat_name`; this switch is comptime-exhaustive, so a missing arm here is a hard build failure the moment `ValidationKind` grows a variant. | `src/daemon/registry.zig:789`–`802` |

Validation order in `validate()`: syntax is checked before uniqueness for each
provider — a malformed name is a defect regardless of whether it also
collides, and reporting the collision first would be misleading. Evidence:
`src/daemon/registry.zig:652`–`676`.

## `stats_provider.zig`

Self-contained module-facing interface, `std`-only, no dependency on
`registry.zig` (the dependency runs the other way: `registry` imports
`stats_provider`, never the reverse). Evidence: `src/daemon/stats_provider.zig:26`.

| Symbol | Role | Evidence |
| --- | --- | --- |
| `Kind` (`counter` / `gauge`) | Metric semantics. | `src/daemon/stats_provider.zig:30` |
| `Category` (`conn`, `traffic`, `reactor`, `tls`, `mesh`, `media`, `security`, `world`, `module`) | Coarse subsystem grouping for `STATS x <category>`. | `src/daemon/stats_provider.zig:41` |
| `ReadFn` | `*const fn (ctx: *anyopaque) i128` — pull-based, allocation-free, called only on the cold render path (`STATS`/scrape), never the hot path. | `src/daemon/stats_provider.zig:65` |
| `Spec` | One declared metric: `prom`, `irc`, `help`, `kind`, `category`, `read`. | `src/daemon/stats_provider.zig:68` |
| `Entry` | `{ module_id, spec }` — the registry's flattened row shape. | `src/daemon/stats_provider.zig:83` |
| `validPromName` | `[a-zA-Z_:][a-zA-Z0-9_:]*` — legal Prometheus identifier. | `src/daemon/stats_provider.zig:97` |
| `validIrcToken` | `[a-zA-Z_][a-zA-Z0-9_]*` — stricter than `validPromName` (no `:`), because the oper dump renders `token = value` and a colon would read as a namespace separator. | `src/daemon/stats_provider.zig:112` |
| `forEachHuman` | `irc = value` per provider — the oper `STATS`/`STATS x` dump. | `src/daemon/stats_provider.zig:130` |
| `forEachStructured` | `onyx_conns_active{module="core",category="conn",kind="gauge"} 5` — machine-readable, same syntax a script would parse off the Prometheus endpoint. | `src/daemon/stats_provider.zig:155` |
| `writePrometheus` | Full HELP/TYPE/sample exposition text, mirroring `server_stats.Stats.writePrometheus`. | `src/daemon/stats_provider.zig:182` |
| `categoryFromToken` | Case-insensitive token → `Category`, `null` on garbage so a caller fails closed with a usage reply instead of dumping everything. | `src/daemon/stats_provider.zig:198` |
| `max_line_len` (512) | Longest rendered line any renderer here emits; an over-long line is skipped, not truncated — a half-written metric is worse than an absent one. | `src/daemon/stats_provider.zig:92` |

All three renderers read the same flat table, so the human dump, the
structured dump, and the Prometheus exposition can never disagree about what a
module exports.

## What did NOT land in this pass: server.zig wiring

`src/daemon/server.zig` was already carrying a large, unrelated, actively
in-flight diff (SESSION RESUME oper-prefix propagation) at the time this
landed, and no module in `src/daemon/modules/*.zig` declares a non-empty
`stats:` list yet — `Registry(mods).stats` is currently always the empty
table. Wiring `Registry(mods).stats` into the daemon's `STATS`/`STATSX`
handlers and the Prometheus HTTP endpoint is deliberately deferred rather than
added to an already-hot file with nothing yet to render:

- No module declares `stats:`, so there is nothing to wire today; adding the
  call site now would be dead code exercising an empty table.
- `server.zig` is under active, unrelated edits; a minimal, uncontested landing
  point is a follow-up module PR once a first provider (e.g. `core` exposing
  `conns_active`) actually exists, not a speculative hook into a file that is
  already hard to review.

Follow-up: once a module declares its first `stats:` entry, wire
`Registry(mods).stats` into the `STATS`/`STATSX` command handler(s) via
`stats_provider.forEachHuman`/`forEachStructured`, and into the Prometheus
endpoint via `stats_provider.writePrometheus`, passing `*server.LinuxServer` as
the erased `ctx` — exactly the same erased-context contract `CommandHandler`
and `LifecycleFn` already use.

## Verification

Both files were verified in isolation (a standalone `zig test` module rooted
at `src/`, bypassing the unrelated in-flight `server.zig` compile error caused
by an unrelated WIP change to `src/proto/ircx_access_store.zig`'s `Request`
union — not part of this change and not touched by it):

- `src/daemon/stats_provider.zig` — 9/9 tests pass standalone.
- `src/daemon/registry.zig` (+ its transitive imports `oper.zig`,
  `../proto/ircx_gate.zig`, and everything reachable from `src/daemon/registry.zig`
  through `src/`) — 179/179 tests pass, including:
  - `Registry.stats aggregates every module's declared providers`
  - `validator rejects a duplicate stats Prometheus name across modules`
  - `validator rejects a duplicate stats STATS token across modules, case-insensitively`
  - `validator rejects a malformed Prometheus stat name`
  - `validator rejects a malformed STATS irc token`

`zig fmt --check` is clean on both files.

## Explicitly out of scope for this change

- `src/crypto/tls_*.zig` — not touched.
- `src/proto/ircx_access_store.zig`, `src/proto/ircx_access_event.zig`,
  `src/proto/root.zig`, `src/daemon/server.zig`'s ACCESS/`.copy`-related switch —
  unrelated in-flight work; the pre-existing `test-exe` compile failure there
  predates this change and is not this change's regression.
