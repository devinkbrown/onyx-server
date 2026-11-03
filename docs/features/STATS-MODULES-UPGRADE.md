# Stats-provider declarations and live metrics

This is a current source contract, reconciled on 2026-11-03. SerpentRegistry has a
module-facing stats-provider interface. The enabled modules currently declare no
nonempty `stats` list, and the daemon does not render `Live.stats` through its IRC
or HTTP metrics paths. Declaration support and live metric export are separate.

## Provider interface

[stats_provider.zig](../../src/daemon/stats_provider.zig) defines:

| Symbol | Contract |
|---|---|
| `Spec` | Prometheus name, IRC token, HELP text, kind, category and read callback. |
| `Entry` | Declaring module ID and provider spec. |
| `Kind` | Counter or gauge semantics. |
| `Category` | `conn`, `traffic`, `reactor`, `tls`, `mesh`, `media`, `security`, `world`, `module`. |
| `ReadFn` | `*const fn (ctx: *anyopaque) i128`; the caller supplies the actual live owner. |
| `validPromName`, `validIrcToken` | Name/token validation before provider-table construction. |
| `forEachHuman`, `forEachStructured`, `writePrometheus` | Bounded renderers over the same supplied entry table. |
| `max_line_len` | 512-byte rendering ceiling; overlong lines are skipped. |

[registry.zig](../../src/daemon/registry.zig) adds `Module.stats`, the exported
stats aliases, `countStats`/`buildStatsTable`, and `Registry(mods).stats`.
Validation rejects invalid metric names and duplicate Prometheus names or
case-insensitive IRC tokens across modules. The table is built at compile time;
adding a provider does not by itself schedule reads or expose it remotely.

## Current live implementation

`LinuxServer.refreshMetricsSnapshotFallible` in [server.zig](../../src/daemon/server.zig) renders
`server_stats.Stats`, module runtime counters, latency statistics and peer health.
IRC `STATS` has its own handler. `MODULES` reports each module's declared stats
count, including zero. There is no registered `STATSX` command and no live promise
of `STATS x <category>` provider routing.

Module lifecycle and hook wiring **are** live through
[module_runtime.zig](../../src/daemon/module_runtime.zig). They were integrated
after the original provider work; old notes about an unrelated ACCESS compile
failure or an unintegrated lifecycle driver are not current release limitations.
See [the module system](../architecture/MODULE-SYSTEM.md) and
[observability](../architecture/observability-stats.md).

## Adding a live provider

Declare its spec on the owning module, provide an allocation-free read callback
with the correct owner and synchronization, and add the intended renderer call
and access policy. Review metric naming, cardinality, counter reset behavior,
output bounds and the availability of disabled/degraded modules. Verify that IRC
and HTTP views use the same accepted provider set before claiming parity.

Provider/registry tests cover formatting, invalid names and collisions. Runtime
and daemon tests cover the separately integrated metrics/lifecycle surfaces.
Use [the testing guide](../guide/testing.md); historical standalone counts are not
current full-suite acceptance. Full release evidence is recorded in
[the 2026-11-03 audit](../audit/release-and-test-speed-2026-11-03.md).
