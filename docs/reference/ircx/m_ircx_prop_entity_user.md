# IRCX user and member entity properties

_The IRCX `PROP` surface for user entities (and per-channel member entities) — writable profile keys, computed read-only built-ins, and their mesh propagation._

User and member properties are served by the same `LinuxServer.handleProp` in
[`src/daemon/server.zig`](../../../src/daemon/server.zig) as channel props, over
the store in
[`src/proto/ircx_prop_store.zig`](../../../src/proto/ircx_prop_store.zig).
Computed user values come from the provider registry in
[`src/proto/ircx_prop_providers.zig`](../../../src/proto/ircx_prop_providers.zig).
Addressed via [`PROP`](m_ircx_prop.md); requires IRCX mode (else `421`).

## Entity forms

| Form | Kind | Who may write |
| --- | --- | --- |
| `nick` | user | the user themselves (`propAccess` → self); operators as `sysop` |
| `#chan:nick` | member | a channel operator of `#chan`; operators as `sysop` |

## Writable user profile keys

`ircx_prop_store.UserProfilePropKey`: `URL`, `GENDER`, `PICTURE`, `BIO`,
`EMAIL`. Arbitrary additional metadata keys are also accepted and stored
generically. A user may set these only on their own entity.

```text
PROP <nick> URL :https://example.test
PROP <nick> BIO :building an IRCX server in Zig
PROP <nick> EMAIL :                     # delete
```

## Computed read-only user built-ins

Provided by `ircx_prop_providers` (scope `.user`), answered ahead of the store
and not client-writable:

| Key | Meaning |
| --- | --- |
| `ACCOUNT` | the user's logged-in account |
| `MEMBER_OF` (alias `MEMBEROF`) | channels the user is on |
| `COUNTRY`, `REGION`, `CITY`, `ASN`, `ASORG` | GeoIP-derived |

The GeoIP keys are read-only and privacy-gated: a cross-user read requires the
requester to be the same user or a network operator; attempts to set or delete
them return `913 ERR_NOACCESS`.

## Mesh propagation

User and member property writes propagate over the `ENTITY_PROP` path
(`propagateLocalEntityProp`) as signed, multi-hop last-writer-wins facts — the
same guarantees as channel properties. The origin uses the node `shortId`; the entity-kind discriminator is signed,
so a relay cannot convert a user fact into a member fact while retaining valid
origin proof. Received facts still need their family-specific admission and
account/lifecycle authorization; a stored public device key is not a bearer token.

## Examples

```irc
IRCX
PROP alice                      ; list alice's visible properties
PROP alice COUNTRY              ; computed GeoIP (self or oper only)
PROP alice PICTURE :https://cdn.example/a.png   ; alice sets her own
PROP #zig:alice ROLE :greeter   ; a channel op annotates a member
```
