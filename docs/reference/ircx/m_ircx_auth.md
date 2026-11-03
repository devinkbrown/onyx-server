# IRCX AUTH

_The IRCX `AUTH` command — a SASL negotiation surface for the legacy, pre-CAP IRCX path, layered over Onyx Server's live SASL mechanisms._

`AUTH` is a real server command registered in
[`src/daemon/modules/ircx.zig`](../../../src/daemon/modules/ircx.zig), handled
by `LinuxServer.handleIrcxAuth` in
[`src/daemon/server.zig`](../../../src/daemon/server.zig). The pure line parser
and reply builders are in
[`src/proto/ircx_auth.zig`](../../../src/proto/ircx_auth.zig); the exchange runs
through the shared `sasl_mechrouter`, so IRCX AUTH and IRCv3
`CAP`/`AUTHENTICATE` share one mechanism backend.

> Onyx Server's primary authentication is IRCv3 SASL over `CAP`/`AUTHENTICATE`. IRCX
> `AUTH` is the alternate path for IRCX clients that negotiate before (or
> without) CAP; it is not the recommended surface.

## Syntax

```text
AUTH <package> <sequence> [:<data>]
```

- `<package>` — a SASL-backed package name. The live set is derived per session
  from the mechanisms actually enabled: `PLAIN`, `EXTERNAL`, `SCRAM-SHA-256`,
  `SCRAM-SHA-512`, `SCRAM-SHA-512-PLUS`, `SESSION-TOKEN`, `OAUTHBEARER`,
  `ANONYMOUS` (plus the GateKeeper packages). The advertised list is reported in
  the `RPL_IRCX` (800) reply — see [IRCX / ISIRCX](#discovery).
- `<sequence>` — `I` (initial), `C` (client continuation), `S` (server
  continuation), or `*` (abort) (`ircx_auth.Sequence`).
- `<data>` — base64 SASL payload for this step (`+` denotes an empty payload).

## Behavior

- **Router-driven exchange.** The first `AUTH` for a package starts a
  `sasl_mechrouter.Router` seeded from the session's enabled mechanisms and TLS
  material (`tls_certfp`, `tls_exporter`); subsequent lines feed payloads to the
  same router until it yields success or failure.
- **Server challenge / ack.** Continuations are emitted as
  `AUTH <package> S [:<data>]`; a successful authorization is acknowledged with
  `AUTH <package> * <ident> <oid>`. Failure and unknown-package replies come
  from `ircx_auth.buildAuthenticationFailedReply` / `buildUnknownPackageReply`.
- **TOTP second factor.** A knowledge-factor package (`PLAIN`, `SCRAM-*`,
  GateKeeper) for a 2FA-enabled account is refused over `AUTH` — that path
  carries no second factor — and the user is told to log in with `IDENTIFY
  <account> <password> <code>`. `EXTERNAL`/`OAUTHBEARER`/`SESSION-TOKEN`/`ANON*`
  are other/continuation factors and pass.
- **On success** the session is logged in (or made a guest), account metadata
  and silence lists are restored, oper elevation is applied where the package
  permits it, and the normal post-registration burst (memo, autojoin,
  welcome) follows.

## Discovery

`IRCX` / `ISIRCX` / `MODE ISIRCX` reply with `RPL_IRCX` (800):
`<state> <version> <package-list> <maxmsg> :*`, where `<package-list>` is this
session's advertised AUTH packages and `<maxmsg>` is `512`. Discovery works
before registration.

## Examples

```irc
ISIRCX
AUTH PLAIN I :<base64 authzid\0authcid\0passwd>
AUTH SCRAM-SHA-256 I :<base64 client-first>
AUTH PLAIN *
```

## Mechanism and credential scope

Discovery advertises only mechanisms wired on this connection. Use the
[SASL matrix](../ircv3-capabilities.md#sasl-mechanisms) for current verifier and
channel-binding conditions. Successful `SESSION-TOKEN` authentication restores
account login; it does not select an exact reusable attachment. `AUTH` is also
subject to the shared account status/factor checks described in
[credential domains](../credential-domains.md).
