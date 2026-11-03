# Connection commands

*Pre-registration handshake, capability negotiation, SASL, heartbeat, and session teardown.*

These commands are accepted through the lower command table for connection-level verbs (`src/daemon/dispatch.zig`). After registration, the module spine gets first chance to handle commands, then falls back to the same lower table for `PASS`/`NICK`/`USER`/`CAP`/`AUTHENTICATE`/`PING`/`PONG`/`QUIT` (`src/daemon/server.zig`). `NICK` and `QUIT` are also registered module commands, and registered `PONG` is accepted by the `feature.misc` module with no reply (`src/daemon/modules/user_query.zig`, `src/daemon/modules/feature_misc.zig`).

Registration completes in the lower dispatcher only after `NICK` and `USER` have both been seen and CAP negotiation is not held open (`src/daemon/dispatch.zig`). The lower dispatcher emits the initial 001-005 welcome numerics and notices (`src/daemon/dispatch.zig`); the live server then registers the nick, sends LUSERS and MOTD, applies admission checks, may elevate SASL oper state, assigns the connection class, and enforces class policy (`src/daemon/server.zig`).

There is no `STARTTLS` command; TLS is listener-level implicit TLS (`src/daemon/server.zig`). There is no lower-table `PROTOCTL` command; unregistered unknown commands are emitted as `ERR_UNKNOWNCOMMAND 421` (`src/daemon/dispatch.zig`).

## PASS

- Syntax: `PASS <token>`
- Description: Records that a pre-registration password was supplied. The handler does not validate a server password; it only updates registration state.
- Privileges: Any pre-registration client.
- Parameters: `token` is required but not otherwise inspected by this handler.
- Replies: None on success.
- Errors: `ERR_ALREADYREGISTRED 462` if already registered; `ERR_NEEDMOREPARAMS 461` if missing.
- Example: `PASS unused`
- Sources: `src/daemon/dispatch.zig`

## NICK

- Syntax: `NICK <nick>`
- Description: Before registration, stores the nick after validating control bytes and the configured `NICKLEN`; the live server withholds the welcome burst until it verifies that a registered account name is owned by the SASL-authenticated account, then reserves the nick and can close the connection on ownership, SACCESS, reservation, nick-delay, or collision failure. After registration, the module handler applies the same account-ownership gate before changing the live nick, updating the world registry, broadcasting `NICK`, updating MONITOR/WHOWAS/event history, and propagating the change across Undertow. Unregistered names remain available to guests. The `=Nick` namespace is reserved
  for synthetic webhook sources and is rejected for real clients, including restore/adoption.
- Privileges: Any client before registration; registered client afterward.
- Parameters: `nick` is required.
- Replies: On registered nick change, broadcasts a `NICK` line to visible peers.
- Errors: pre-registration missing `nick` returns `ERR_NEEDMOREPARAMS 461`; registered missing `nick` returns `ERR_NONICKNAMEGIVEN 431`. Invalid, blocked, reserved, or registered-but-not-owned nicks return `ERR_ERRONEUSNICKNAME 432`; collisions return `ERR_NICKNAMEINUSE 433`; nick-delay holds return `ERR_UNAVAILRESOURCE 437`. A registered-name rejection says that authentication is required and never emits `001` first.
- Example: `NICK suzu`
- Sources: `src/daemon/dispatch.zig`, `src/daemon/server.zig`, `src/daemon/modules/user_query.zig`

## USER

- Syntax: `USER <username> <mode> <unused> :<realname>`
- Description: Pre-registration only. Stores the username and realname after control-byte validation. Once `NICK`, `USER`, and capability negotiation permit registration, the lower dispatcher emits the initial welcome numerics; the live server assigns the connection class later in the post-registration admission sequence.
- Privileges: Any pre-registration client.
- Parameters: Four parameters are required by the lower command table; the handler uses parameter 1 as username and parameter 4 as realname.
- Replies: May complete registration and emit welcome numerics when `NICK`, `USER`, and capability negotiation permit it.
- Errors: `ERR_ALREADYREGISTRED 462`; `ERR_NEEDMOREPARAMS 461`.
- Example: `USER suzu 0 * :Onyx Server User`
- Sources: `src/daemon/dispatch.zig`

## CAP

- Syntax: `CAP LS [302]`, `CAP REQ :<cap>[ <cap>...]`, `CAP LIST`, `CAP END`
- Description: Dispatches capability negotiation to the session capability handler. `LS` enters negotiation and emits the advertised list, `REQ` enters negotiation and emits `ACK` or `NAK`, `LIST` emits negotiated caps, and `END` completes negotiation. cap-notify is advertised from a static set, so CAP NEW and CAP DEL stay unused. draft/whoami and file-upload stay off this list; file-upload remains only on the unused proto/cap.zig table.
- Privileges: Any client, before or after registration.
- Parameters: A subcommand is required. `REQ` requires a capability list. Capability values are accepted only when they match the advertised value or one comma-separated offered item.
- Replies: Raw `CAP` replies; no numeric on normal success.
- Errors: `ERR_INVALIDCAPCMD 410` for subcommands other than `LS`, `LIST`, `REQ`, or `END`; `ERR_NEEDMOREPARAMS 461` for a missing subcommand or missing `REQ` list.
- Example: `CAP LS 302`
- Supported capabilities: use the complete [live CAP table](../protocol/caps.md). SASL mechanisms and STS values are built from this connection's actual policy; a static fallback list is not a guarantee of availability.
- Sources: `src/daemon/dispatch.zig`

## AUTHENTICATE

- Syntax: `AUTHENTICATE <mechanism-or-payload>`
- Description: Runs SASL. The mechanism token starts a router for `PLAIN`, `EXTERNAL`, `SCRAM-SHA-256`, `SCRAM-SHA-512`, `SCRAM-SHA-512-PLUS` when its exporter is configured, `SESSION-TOKEN`, `OAUTHBEARER`, or `ANONYMOUS` when the corresponding session checker is configured; subsequent lines carry mechanism payloads. A successful exchange lowercases and stores the account, emits login numerics, and lets registration finish.
- Privileges: Any pre-registration client that has negotiated the `sasl` capability. Already registered clients are rejected.
- Parameters: One mechanism token or payload chunk is required. `*` aborts when used at the appropriate phase.
- Replies: Raw `AUTHENTICATE <challenge>` lines, `RPL_LOGGEDIN 900`, `RPL_SASLSUCCESS 903`.
- Errors: `ERR_ALREADYREGISTRED 462`, `ERR_SASLFAIL 904`, `ERR_SASLABORTED 906`, `ERR_NEEDMOREPARAMS 461`.
- Example: `AUTHENTICATE PLAIN`
- Sources: `src/daemon/dispatch.zig`

## PING

- Syntax: `PING <origin>`
- Description: The registered fast path routes `PING` to the lower command table, which replies with `PONG <server> :<origin>`.
- Privileges: Any client.
- Parameters: `origin` is required by the handler.
- Replies: Raw `PONG`.
- Errors: `ERR_NOORIGIN 409` when the origin is missing.
- Example: `PING 12345`
- Sources: `src/daemon/server.zig`, `src/daemon/dispatch.zig`

## PONG

- Syntax: `PONG <origin>`
- Description: Acknowledges a heartbeat. Before registration, the lower table accepts it with no reply when an origin is present and returns `409` when it is absent. After registration, the module handler accepts `PONG` and intentionally emits no reply.
- Privileges: Any client, in either the lower table or the registered module table.
- Parameters: Lower-table `PONG` requires an origin; the registered module handler ignores invocation details.
- Replies: None.
- Errors: Lower table can emit `ERR_NOORIGIN 409` when the origin is missing.
- Example: `PONG 12345`
- Sources: `src/daemon/dispatch.zig`, `src/daemon/modules/feature_misc.zig`

## QUIT

- Syntax: `QUIT [:reason]`
- Description: Before registration, marks the session closing. After registration, closes this physical attachment. Logical QUIT/offline, WHOWAS
  and nick-delay side effects follow the shared-session lifecycle: a surviving
  sibling must retain the logical identity and channel state. The final logical
  departure performs ordinary world/nick cleanup.
- Privileges: Any client.
- Parameters: Optional reason; registered handler defaults to `Client quit`.
- Replies: Broadcast `QUIT` to visible peers; no numeric success reply.
- Errors: None specific in the handler.
- Example: `QUIT :done`
- Sources: `src/daemon/dispatch.zig`, `src/daemon/modules/user_query.zig`, `src/daemon/server.zig`
