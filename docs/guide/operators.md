# Operators

*Configure operator privileges, connection classes, flood control, and network-wide event subscriptions.*

Orochi operators are SASL-only. `OPER` never accepts a password; it returns an error instructing the user to authenticate by SASL (`src/daemon/server.zig:8300`). After successful SASL, an account matching `[[opers]]` is elevated automatically (`src/daemon/server.zig:8308`).

## Connection classes

A connection class is a named bundle of per-connection resource, admission, and flood policy, assigned to a client at registration by matching the connection's source IP, TLS status, SASL authentication, operator status, and ident/host. The **first class (in file order) whose match criteria are all satisfied wins**; a class with no criteria is a catch-all fallback. Two built-in classes always exist: `user` (regular clients) and `server` (mesh links) (`src/daemon/conn_class.zig:8`).

### Match criteria

| Criterion | Meaning | Examples |
|---|---|---|
| `match` | Array of source IP/CIDR (IPv4 and IPv6) | `["10.0.0.0/8", "2001:db8::/32", "192.168.1.5"]` |
| `match_tls` | Match only implicit-TLS connections | `true` |
| `match_account` | Match only SASL-authenticated connections | `true` |
| `match_oper` | Match only opered-up connections | `true` |
| `match_ident` | Glob pattern on the connection's ident/username | `"admin*"` |
| `match_host` | Glob pattern on the connection's hostname | `"*.example.com"` |

All specified criteria must match for the class to apply. See `docs/reference/config.md` `[class.<name>]` for the complete configuration table.

### Policy knobs

Per-class policy fields override their `[limits]` global counterparts. A `0` value means "inherit the global limit" unless noted otherwise.

| Policy | Meaning | Default |
|---|---|---|
| `sendq` | Outbound SendQ ceiling in bytes | `1M` (`8M` for server class) |
| `recvq` | Inbound line ceiling in bytes; `0` = physical line buffer | `0` |
| `max_clients` | Max live connections in this class; `0` = unlimited | `0` |
| `max_per_ip` | Max concurrent connections per IP in this class; `0` = unlimited | `0` |
| `max_channels` | Max channels a member may join; `0` = inherit global `chanlimit` | `0` |
| `max_targets` | Max PRIVMSG/NOTICE targets; `0` = inherit global `maxtargets` | `0` |
| `monitor` | Max MONITOR entries; `0` = inherit global `monitorlimit` | `0` |
| `silence` | Max SILENCE masks; `0` = inherit global `silencelimit` | `0` |
| `ping_interval` | Per-class PING keepalive interval; `0` = inherit global | `0` |
| `ping_timeout` | Per-class grace after PING before disconnect; `0` = inherit global | `0` |
| `register_timeout` | Per-class registration handshake timeout; `0` = inherit global | `0` |
| `flood_lines` | Max inbound lines per `flood_window`; `0` = no flood limit | `0` |
| `flood_window` | Window for `flood_lines`; `0` = default `10s` when only `flood_lines` is set | `0` |
| `require_tls` | Refuse admission unless connection is TLS | `false` |
| `require_sasl` | Refuse admission unless SASL-authenticated | `false` |
| `flood_exempt` | Exempt from flood/throttle enforcement | `false` |
| `nick_delay_exempt` | Exempt from nick-delay holds; member may take a held nick immediately | `false` |

### Example

```toml
[class.user]
# Built-in: the catchall for regular clients
sendq = "1M"
recvq = "8K"
max_per_ip = 5
max_channels = 50

[class.server]
# Built-in: every S2S mesh link
sendq = "8M"
recvq = "1M"

[class.trusted]
# Custom: local/corporate VPN clients
match = ["10.0.0.0/8", "::1"]
match_tls = true
sendq = "16M"
max_per_ip = 0
flood_exempt = true

[class.restricted_net]
# Custom: throttled public wifi
match = ["203.0.113.0/24"]
flood_lines = 10
flood_window = "10s"
require_tls = true
```

### Inspecting classes live

```text
/STATS Y
```

Numeric **218 RPL_STATSYLINE** reports one line per registered connection class with its full policy, match summary, and live member count (`src/daemon/server.zig:10356`). Output includes the class name, policy fields (sendq, recvq, max_clients, max_per_ip, max_channels, max_targets, monitor, silence, timeouts, flood settings), match facets (match criteria, TLS-only, account-only, oper-only), CIDR count, and current member count (`src/daemon/server.zig:10343`).

### SendQ and RecvQ

**SendQ (outbound):** each connection maintains an ~8 KiB inline send buffer plus a heap overflow, bounded by the per-class `sendq` ceiling. The buffer is io_uring zero-copy safe — the armed send buffer is never moved or freed during flight. Exceeding the ceiling drops appended data with an "output too small" error (`src/daemon/conn_class.zig`).

**RecvQ (inbound):** pending unterminated lines accumulate in an inline line buffer and spill to a heap overflow once they outgrow it, bounded by the per-class `recvq` ceiling. A `recvq` of `0` inherits the daemon's physical line-buffer default. A line exceeding the ceiling drops the connection (LineTooLong error).

## Nick delay

Nick delay is an anti-camping protection: when a registered account's nick is released (by the owner disconnecting or sending `QUIT`), the daemon holds that nick against reuse for a configured window (`src/daemon/nick_delay.zig:1`).

### Configuration

```toml
[limits]
nick_delay = "30s"  # or "0" to disable (the default)
```

Set `[limits].nick_delay` to a duration string (`"30s"`, `"1m"`, and so on) to enable it. `"0"` disables nick delay entirely (`src/daemon/config_format.zig:172`).

### Behavior

- A nick is held **only when its owner exits** (disconnect or `QUIT`). Voluntary `NICK` changes do not apply nick delay.
- During the hold window:
  - The **owning account** (if the releaser was SASL-authenticated) may reclaim the nick immediately.
  - **Server operators** (any opered connection) bypass the hold entirely.
  - Connections flagged `nick_delay_exempt` in their class bypass the hold.
  - **Everyone else** is refused with numeric **437 ERR_UNAVAILRESOURCE**: `"Nick is held (nick delay); try again shortly"` (`src/daemon/server.zig:5885`).
- Once the window expires, the nick is free for anyone to claim.

### Per-class exemption

A connection class can exempt its members from nick-delay holds via the `nick_delay_exempt` policy flag (`src/daemon/nick_delay.zig:8`):

```toml
[class.services]
match = ["10.0.0.5"]
nick_delay_exempt = true
```

Members of this class may take a held nick without waiting, just like operators.

### Live status

`INFO` reports nick-delay status when enabled:

```text
/INFO
```

Look for a line such as `"Nick delay: 30000ms hold on release - 5 nick(s) currently held"` (`src/daemon/server.zig:19219`).

## Per-class flood control

Each connection class drives a single runtime flood guard (`src/daemon/flood_guard.zig`) from its `flood_lines`/`flood_window` budget. The guard is more than a line counter: keep-alives (`PING`/`PONG`) are free, `PRIVMSG`/`NOTICE`/`JOIN` are weighted, a distinct-PRIVMSG-target spread check counters spray-spam, and sustained over-budget traffic accrues decaying excess strikes toward an `ERROR :Excess Flood` disconnect. It retunes live on `REHASH`.

### Configuration

```toml
[class.restricted_net]
match = ["203.0.113.0/24"]
flood_lines   = 10     # Command-rate budget per flood_window
flood_window  = "10s"  # Enforcement window (default if only flood_lines set)
flood_excess  = 0      # Excess strikes before disconnect (0 = auto: max(20, 2*flood_lines))
flood_targets = 0      # Distinct PRIVMSG targets/window before spread throttle (0 = auto: max(8, flood_lines))

[class.exempt_vip]
flood_lines = 0       # No flood limit
flood_exempt = true   # Exempt from throttle/flood entirely
```

### Behavior

- **`flood_lines`**: Command-rate budget (weighted token bucket) per `flood_window`. `0` = no limit.
- **`flood_window`**: Duration for the budget. If only `flood_lines` is set, the window defaults to `10s`.
- **`flood_excess`**: Excess strikes tolerated before disconnect; `0` = auto (`max(20, 2×flood_lines)`). Each over-budget command adds a strike; strikes decay ~1/s, so a brief burst recovers but a sustained flood is cut with `ERROR :Excess Flood`. Throttled lines are still processed (no silently dropped user input) — only the excess threshold disconnects.
- **`flood_targets`**: Distinct PRIVMSG targets a client may spray per `flood_window` before the spread-spam throttle adds excess; `0` = auto (`max(8, flood_lines)`).
- **`flood_exempt`**: When true, the class entirely bypasses the flood guard and throttle enforcement.
- **S2S server links** are always exempt (the `server` class carries mesh traffic which may burst immediately after connection).
- Only registered connections are subject to flood control; the registration handshake itself is not throttled by these limits.

## Network raid guard

Beyond the per-channel `+j` join-throttle mode, `[limits].raid_joins` and `raid_window` apply a **default** join-throttle to every channel that has no explicit `+j`. When more than `raid_joins` clients join such a channel within `raid_window`, further joins are denied (`ERR_THROTTLE`) and a one-shot `FLOOD` raid alert is published to subscribed operators on the Event Spine. An explicit `+j` always overrides the default; operators and invited users bypass it; `raid_joins = 0` disables it.

```toml
[limits]
raid_joins  = 20     # default join-throttle for channels without +j (0 = disabled)
raid_window = "10s"
```

Operators can also plant **spam-trap honeypots** with `SPAMTRAP ADD NICK <nick>` / `SPAMTRAP ADD CHAN <#channel>`: a non-oper that contacts a trap trips a `FLOOD` alert and is flagged for `WARD` follow-up. See [commands/oper-moderation.md](../reference/commands/oper-moderation.md).

### Live-ward enforcement

A `WARD` (network ban) now bites **already-connected** clients, not just the next reconnect. When a ward is added locally by the `WARD` command or arrives propagated from another mesh node, the daemon sweeps every live, registered, non-oper session and applies the first matching ward's action immediately (`src/daemon/server.zig:18713`, `src/daemon/server.zig:18730`):

- `refuse` / `expel` → the client is closed with `Closing Link: <name> (Banned: <reason>)`.
- `quarantine` → the session is restricted in place (no `JOIN`, no `PRIVMSG`/`NOTICE`), no teardown.
- `require_auth` → authenticated subjects pass; everyone else is expelled.

Operator sessions and S2S links are exempt. The sweep reuses the registration checkpoint's matcher exactly — the same facets and the same previous-cloak-key fallback — so a live raid is cut off the moment the ban lands rather than one reconnect later.

## Host cloaking

By default every client's real IP is hidden behind an HMAC [cloak](../reference/host-cloaking.md), configured under `[cloak]`. Two 0.4.0 changes affect operators.

### Argon2id key derivation (migration note)

The `[cloak] secret` passphrase is stretched through **Argon2id** (memory-hard) with a fixed domain-separation salt to derive the cloak key, replacing the previous bare `SHA256(secret)` (`src/main.zig:472`). Because the IPv4 input space is fully enumerable, the model rests on key secrecy, and a low-entropy operator passphrase must not be offline brute-forceable. Derivation is deterministic, so cloaked hosts stay stable across restarts and identical mesh-wide.

**One-time migration on upgrade:** the derived key changes, so the first boot after this upgrade **reshuffles every client's cloak once**. Pre-upgrade host/subnet `WARD` bans written against the old SHA256-derived cloaks **do not carry over** — the daemon can no longer reproduce that key. The `[cloak] previous_secret` grace window covers only future rotations under the new Argon2id KDF, not the SHA256→Argon2id transition itself. Expect to re-establish any long-lived cloak/subnet bans after upgrade.

### Anonymous-cloak rotation (`anon_epoch_secs`)

```toml
[cloak]
anon_epoch_secs = 86400   # default 24 h; 0 disables rotation
```

When non-zero, an **unauthenticated** (not-logged-in) client is given an OPAQUE cloak salted by the current wall-clock epoch, `floor(now/anon_epoch_secs)` (`src/daemon/config_format.zig:646`, `src/proto/cloak.zig:187`). A static-IP anonymous user is therefore neither linkable across epochs nor able to leak subnet co-membership. It is wall-clock based so every mesh node agrees on the epoch. Valid range is `0`–`31536000` s.

**Operator impact:** because anonymous cloaks rotate and are opaque, host/subnet `WARD` bans on anonymous abusers are short-lived and not subnet-bannable — moderation of anonymous abuse shifts to **account bans plus registration friction** (which the opaque cloaks are designed to require). **Logged-in clients are unaffected**: they keep a stable, moderatable account/hierarchical cloak. Set `anon_epoch_secs = 0` to restore the pre-2026-07 stable-cloak behavior for anonymous clients (at the cost of forever-linkability and subnet co-membership exposure).

## Server links and peer inspection

### Per-link statistics

```text
/STATS l
```

Numeric **211 RPL_STATSLLINE** reports one line per established S2S peer link with `sendq_cap` (the `server` class SendQ ceiling), queued bytes currently pending, and link uptime (`src/daemon/server.zig:10378`). Use this to monitor mesh health and detect SendQ backlog on remote links.

### Mesh health commands

Operators with `mesh_admin` privilege can inspect and manage the mesh:

| Command | Purpose |
|---|---|
| `MESH` or `NETSTAT` | Direct S2S peer/link health, reachability, partition summary (`src/daemon/server.zig:10218`, `src/daemon/server.zig:10308`). |
| `ROUTE` | Current routing table: this node plus established one-hop peers (`src/daemon/server.zig:10452`). |
| `NETHEALTH` | Sazanami-style liveness view using peer RTT and idle time (`src/daemon/server.zig:10474`). |
| `CONNECT <host> <port>` | Open outbound S2S to a peer (`src/daemon/server.zig:6304`). |
| `SQUIT <server>` | Tear down an S2S link by server name (`src/daemon/server.zig:6371`). |

## Network-wide operator events

Operator-facing events are delivered over the **Event Spine**: an event raised on
any node is fanned out to every mesh node and rendered with the **originating**
server name, so operators see the whole network from a single node. Two opt-in
subscription models ride it:

- **Category feed** — `EVENT ADD <category>` (e.g. `CONNECT`, `DISCONNECT`,
  `FLOOD`, `KILL`, `SERVER_LINK`, `OPER_ACTION`) subscribes to a snomask-style
  stream. User connects/disconnects/nick changes and the raid/flood/oper-action
  alerts all publish here, so subscribing on one node surfaces matching events
  network-wide (carried as the signed `OPER_EVENT` S2S frame). `EVENT LIST` shows
  your subscriptions; `EVENT DEL <category>` unsubscribes.
- **Targeted OBSERVE feed** — `EVENT OBSERVE <mask> [actions…]` installs a standing
  `nick!user@host` glob filter (optionally narrowed to `connect`/`quit`/`nick`/
  `oper`). A matching subject's lifecycle is pushed as
  `:<origin-server> EVENT <you> OBSERVE <action> <nick>!<user>@<host> acct=…`,
  carrying the subject's **real, uncloaked** host (operator-trust). OBSERVE matches
  subjects on **every** mesh node (signed `OBSERVE_EVENT` frame); `EVENT OBSERVE
  LIST` shows the active filter and `EVENT OBSERVE OFF` clears it.

`EVENT BROADCAST :<text>` sends a one-shot network-wide oper announcement (this is
the WALLOPS path — there is no `+w` user mode). See
[reference/commands/ircx.md](../reference/commands/ircx.md) for full `EVENT` syntax.

## Account binding

```toml
[sasl]
account_db = "/var/lib/orochi/accounts.wal"

[[opers]]
account = "alice"
class = "netadmin"
title = "Network Guardian"
```

`account_db` opens an OroStore account backend and wires PLAIN, SCRAM-SHA-256, and EXTERNAL into the live server (`src/main.zig:177`, `src/main.zig:193`). `[[opers]].account` is required and must be non-empty (`src/daemon/config_format.zig:433`, `src/daemon/config_format.zig:481`). `class` names an operator group, and `title` is optional WHOIS/operator display text (`src/daemon/config_format.zig:436`, `src/daemon/config_format.zig:441`).

## Privilege classes

Define privilege bundles with `[[oper_groups]]`:

```toml
[[oper_groups]]
name = "observer"
privileges = ["audit_read", "event_subscribe"]

[[oper_groups]]
name = "netadmin"
inherits = "observer"
privileges = ["server_rehash", "server_restart", "mesh_admin", "client_kill"]
```

Privilege strings must match the `oper.Privilege` enum names exactly (`src/daemon/oper.zig:36`):

| Privilege | Meaning in source |
|---|---|
| `server_rehash` | REHASH and config reload authority. |
| `server_restart` | RESTART authority. |
| `server_shutdown` | DIE/shutdown authority. |
| `client_moderate` | WARD/SHUN/quarantine-style client controls. |
| `channel_moderate` | FORCE/CLEAR/channel takeover class controls. |
| `client_kill` | KILL authority. |
| `mesh_admin` | CONNECT/SQUIT and mesh routing control. |
| `service_admin` | Services administration. |
| `server_admin` | Network administrator tier. |
| `oper_grant` | Grant/revoke operator status. |
| `oper_spy` | Private/audit visibility such as real host/IP. |
| `event_subscribe` | Event Spine subscription authority. |
| `audit_read` | Audit read authority. |
| `oper_override` | Force/SA-style override authority. |
| `limit_exempt` | Bypass all per-class connection caps (clone limits by IP/account/host). |

Unknown privilege strings are ignored during config-boot conversion (`src/daemon/config_boot.zig:159`). If an operator class is missing, or its effective privileges are empty, boot skips that operator binding (`src/daemon/config_boot.zig:174`, `src/daemon/config_boot.zig:179`). Use explicit, non-empty groups.

Group inheritance is bounded to 32 parent links (`src/daemon/operator_groups.zig:11`). Effective privileges are the union of the group and its ancestors (`src/daemon/operator_groups.zig:88`).

## Reload behavior

When booted with a config file, `REHASH` re-reads the same path (`src/main.zig:112`, `src/daemon/server.zig:10031`). `REHASH` rebuilds account-to-operator bindings but assigns full privileges rather than recomputing `[[oper_groups]]` (`src/daemon/server.zig:10052`, `src/daemon/server.zig:10062`). Existing sessions keep their current operator state (`src/daemon/server.zig:10028`).
