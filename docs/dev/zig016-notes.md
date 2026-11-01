# Zig 0.16 notes and worker integration rules

> **Superseded / historical — preserved as evidence.** This document is a point-in-time record and does not describe the current source or fleet. Current truth: [docs hub](../README.md) and [production paths](../ops/onyx-server-paths.md). Do not execute it as a current procedure.

*Historical design note: records Zig 0.16 API facts and worker integration rules for internal Onyx Server development.*

Onyx Server targets **Zig 0.16.0**. The standard library differs significantly from older Zig releases; code written from memory of 0.11–0.14 will not compile reliably. Verify every change by compiling.

## Confirmed Zig 0.16 API facts

These facts were hit during scaffolding:

- **No `std.time.milliTimestamp` / `nanoTimestamp` / `Timer` / `Instant`.** Wall and monotonic clock helpers were removed from `std.time` (only unit constants + `epoch` remain). For monotonic time use:

  ```zig
  var ts: std.os.linux.timespec = undefined; // fields: sec: isize, nsec: isize
  _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts);
  const ms = @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000_000);
  ```

- **No `std.testing.refAllDeclsRecursive`.** Use `std.testing.refAllDecls(@This())` plus explicit `_ = @import("...");` to pull in sibling tests.
- **`build.zig` shape:** executables use `.root_module = b.createModule(.{ .root_source_file, .target, .optimize, .imports })`; `b.addModule(name, .{ .root_source_file, .target })`; tests use `b.addTest(.{ .root_module = ... })`. See the repo's build.zig; do not edit it.
- **Console output:** use `std.debug.print(fmt, args)` (goes to stderr). Avoid the old `std.io.getStdOut().writer()` API; the std.Io/Writer surface was overhauled. If you need real I/O, route it through the Reactor seam, not std directly.
- `@typeInfo` tags are lowercase in 0.16 (e.g. `.@"struct"`, `.@"enum"`, `.pointer`,
  `.int`). Verify against `/usr/lib/zig/std/builtin.zig` if you use them.
- When unsure about any std API, grep `/usr/lib/zig/std/` and then compile.

## Verification requirement

Your deliverable is not done until it compiles and its tests pass under 0.16:

```sh
zig test path/to/your_file.zig
```

Each file you create must be self-contained (import only `std`) so it can be tested in isolation. Iterate until green. Do not hand back code you have not compiled.

## Integration rules

- Create only the file(s) you are assigned, at the exact path given. Add new files; do not delete.
- **Do not edit** `src/root.zig`, `build.zig`, `build.zig.zon`, or any package root (`src/*/root.zig`). The orchestrator (Claude) wires new files into the package roots during integration. If you wire them yourself you create merge conflicts.
- Put `test { ... }` blocks in your file covering the core behavior (aim high; this is
  a correctness-critical systems project).
- Match the style of `src/substrate/reactor.zig`: `//!` module doc comment, `//` doc
  comments on public decls, PascalCase types, camelCase functions, snake_case fields/vars.
- No `unreachable`/`@panic` on attacker-reachable input; handle errors explicitly.
- Keep files focused (<800 lines). Prefer caller-provided buffers/slices over hidden
  allocation in hot-path code.

## Design references

- `docs/architecture/00-overview.md` — subsystems, request flow, and source map (authoritative, source-cited).
- `docs/reference/glossary.md` — codename key (Undertow, Mooring, Ripple, Helix, Armor, Ringlane, …).
- `docs/reference/config.md` — full config schema, cited to `src/daemon/config_format.zig`.

## Clean-room and no-legacy mandate

This mandate applies to every module and has highest priority.

Onyx Server is a **clean-room, modern, inventive** IRC daemon. Do not port or copy legacy IRC daemon code. Every system is designed from first principles for an IRCX/IRCv3 + CRDT mesh world.

**Banned legacy behavior — never implement, and remove if found:**

- WALLOPS / OPERWALL  → use the **Event Spine** `.announce` category (oper subscriptions).
- snomask `+s` user modes / `sendto_realops_snomask` → **Event Spine** typed events + IRCX EVENT subscriptions.
- WEBIRC / IP-spoof gateways → web clients connect via **WebSocket** directly.
- `/OPER` command, oper passwords, host/IP masks, RSA challenge → **oper = SASL auth only** (certfp EXTERNAL / SCRAM).
- server `PASS` as authentication → **SASL** (PASS may only select a connection class, never authenticate).
- Exception: **LINKS / MAP are kept** (user decision 2026-06-02), but reimagined: they render the
  **Undertow mesh** (nodes/peers), not a TS6 spanning tree. Implement them as mesh introspection.
- ident / RFC1413 lookups → dead protocol; identity = TLS certfp / SASL.
- TS6 / netburst / SJOIN / text S2S → **Undertow** binary CRDT mesh only.
- Embedded Python / CPython modules → **WASM plugins** (OroWasm) or native Zig only. No Python.
- DCC special-casing, legacy STATS letter soup, ctcp-flood quirks → omit or modernize.

**Positive mandate:** prefer IRCv3 (standard-replies, message-tags, batch, labeled-response, CHATHISTORY),
IRCX (EVENT/PROP/ACCESS), CRDT-mesh-native semantics, typed events, capability tokens, and constant-time
crypto. When a legacy feature has no modern equivalent, invent a principled one and name it; do not port.

**Services = internalized native commands (no bots):** accounts/channels/memos are exposed as real
server commands (REGISTER, IDENTIFY, GROUP, DROP, LOGOUT, CREGISTER, ACCESS, AKICK, MEMO, VHOST, ...)
with IRCv3 standard-replies (FAIL/WARN/NOTE) + structured numerics, not pseudo-client bots
(no NickServ/ChanServ PRIVMSG targets). In-process services — real server commands, no pseudo-clients — with cleaner messaging.
The services.zig backend stays I/O-free (typed results); the daemon command layer wraps it natively.

## Cross-platform mandate

Onyx Server targets **x86_64/aarch64 on linux, macos, freebsd, and windows**. Write portable code:
- Never call `std.os.linux.*` directly in portable modules. Gate OS-specifics behind
  `comptime switch (@import("builtin").os.tag)`. Provide a portable fallback for every fast path.
- **Reactor:** io_uring is a Linux-only fast path behind the `Reactor` seam. The portable backend is
  poll/epoll (linux), kqueue (macos/bsd), IOCP/WSAPoll (windows). All daemon/protocol logic talks to
  `Reactor`, never to a syscall directly.
- **Monotonic time:** no `std.os.linux.clock_gettime` in portable code — use a `Reactor`-provided clock
  (posix `clock_gettime` via std.c on mac/bsd, `QueryPerformanceCounter` on windows).
- **Randomness:** getrandom (linux), arc4random_buf (mac/bsd), BCrypt/RtlGenRandom (windows) — dispatch
  by target (see crypto/random.zig).
- **Linux-only features** (io_uring, kTLS, buf_ring, eBPF, SCM_RIGHTS fd-passing) must be `comptime`
  gated and have a portable degraded path; never break the build on non-linux targets.
- Sockets: prefer `std.posix`/`std.net`; Windows needs the winsock path. Avoid raw `linux.fd_t` in
  cross-platform signatures (use `std.posix.fd_t` / `std.posix.socket_t`).
- CI/build must `zig build -Dtarget=` for: x86_64-linux, aarch64-linux, aarch64-macos, x86_64-windows,
  x86_64-freebsd. A new module is not done until it at least compiles for all five (Linux-only paths
  comptime-excluded elsewhere).
