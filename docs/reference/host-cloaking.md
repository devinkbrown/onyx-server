# Onyx Server host cloaking

*How Onyx Server masks a client's real address from other users, and how an operator recovers the real identity — locally and across the mesh.*

Onyx Server never shows a client's raw IP or reverse-DNS name to other users by
default. The visible host is a deterministic **cloak**: a keyed one-way token
that hides the address while still supporting coherent wildcard bans. The real
identity is surfaced only to operators (and to the user themselves), and only
over channels safe to carry it. This document describes the cloak engine, the
operator's view, and the `[cloak]` configuration as they exist in the source
tree; it complements
[../architecture/mesh-security.md](../architecture/mesh-security.md) (how the
secured mesh leg is authenticated).

## The cloak engine (v2)

The engine is [src/proto/cloak.zig](../../src/proto/cloak.zig). Every cloak
segment is a keyed **HMAC-SHA256** token over a *cumulative prefix* of the real
address (`macTag`, `token32`, `token64`). Because each segment depends only on
the prefix up to that point:

- the same real input + key always yields the same cloak (deterministic);
- a different key yields a completely different, unlinkable cloak;
- two addresses in the same subnet share the broad-prefix segments and differ in
  the specific ones, so subnet bans keep working without exposing the raw
  address.

The full-address token is **64 bits** (16 hex, `full_token_hex_len` /
`token64`); the coarser subnet-prefix tokens are **32 bits** (8 hex,
`token_hex_len` / `token32`). A 32-bit token birthday-collides around 65k
distinct addresses, so the full-address token was widened to 64 bits to make two
real addresses effectively never share a cloak. HMAC domain tags are versioned
(`ip4/v2/32|`, `ip6/v2/64|`, `ip4/v2/opq|`, …) so token families and scheme
versions can never be related. Key bytes are wiped after every use (`secureZero`
in `macTag`).

`cloak()` routes on `classify()`:

```text
IPv4  a.b.c.d      -> <f/32>.<t/24>.<t/16>.<t/8>.a<asn>.<cc>.ip.onyx
IPv6  2001:db8::1  -> <f/128>.<t/64>.<t/56>.<t/48>.<t/32>.a<asn>.<cc>.ip6.onyx
opaque             -> <32 hex>.opq.onyx          (v3; 128 bits)
opaque + epoch     -> <32 hex epoch>.opq.onyx    (anon auth-split; see below)
opaque v4 + epoch  -> <32 hex>.e<epoch>.c<seconds>.opq4.onyx
account            -> kain.users.onyx
```

The most specific token comes **first** (leftmost), matching DNS semantics where
the rightmost labels are the broadest — masking the leading labels while keeping
a shared tail is what makes wildcard bans coherent. `cloakIPv4` masks at /24,
/16, and /8; `cloakIPv6` at /64, /56, /48, and /32.

### GeoIP mixed in as ban-able labels

`appendGeo` inserts the ISO country and origin AS number as two visible labels
`a<asn>.<cc>` between the masked IP tokens and the `ip`/`ip6` marker. This lets
an operator ban a country (`*.us.ip.<net>`) or an ASN (`*.a13335.*.ip.<net>`)
while the exact address stays masked. Unknown geo renders the stable
placeholders `a0` (unknown ASN) and `xx` (unknown/invalid country, via
`appendCountry` / `unknown_country`), so the cloak shape never varies. The geo
labels **do not perturb the IP tokens**, so subnet bans stay geo-independent.
The server fills `Geo` from its MaxMind databases in `cloakGeo`
([src/daemon/server.zig](../../src/daemon/server.zig)); any miss falls back to
`Geo.none`.

## Hierarchical vs opaque

`[cloak] mode` selects the IP-cloak granularity; the tradeoff is
**subnet-ban-ability vs. maximum privacy**:

| `mode` | Form (`cloak` fn) | Subnet-bannable? | What leaks |
| --- | --- | --- | --- |
| `hierarchical` (default) | `cloakIPv4` / `cloakIPv6` | Yes — shared prefix tokens + `a<asn>.<cc>` labels | Which users share a subnet; country + ASN |
| `opaque` | `cloakOpaqueV3` → `<32 hex>.opq.<suffix>` | No | Nothing — one 128-bit token, no subnet hierarchy, no geo |

Opaque emits a single token over the whole address (`opaque_marker = "opq"`),
so nothing about the address leaks — not even country/ASN or which users share
a subnet — at the cost that opaque cloaks cannot be subnet-banned. The daemon
uses the v3 128-bit token (`cloakOpaqueV3`, domain tags `ip4/v3/opq|` /
`ip6/v3/opq|`). The v2 64-bit `cloakOpaque` function stays in the engine so a
ban written against an older public token can still be recognized; other users
do not see that token. Two addresses in the same /24 share nothing under opaque.

## Per-account cloak

With `[cloak] account_cloak = true`, a logged-in client's visible host becomes
the friendly, stable `<account>.users.<suffix>` (`cloakAccount`,
`account_subdomain = "users"`) that follows them across IPs and devices. It is
**key-free** — no secret is involved, so it is stable across restarts and key
rotation. The server selects it in `applyVisibleHost` in the order **account
cloak → opaque → hierarchical**, and re-applies it after a post-registration
login via `maybeApplyAccountCloak`, which fans a CHGHOST out to common channels.
An explicit **VHOST persona sets the host directly and still wins** — it is not
recomputed by `applyVisibleHost`. An unusable account label (or a logged-out
client) falls through to the IP cloak. Loopback (`127.x` / `::1`) always stays
the conventional `localhost`.

Canonical account names that already fit one DNS label retain that form.
Names requiring lossy sanitization or truncation instead use
`<friendly>.<128-bit account digest>.users.<suffix>`. The extra label prevents
distinct permitted names such as `alice_foo`, `alice.foo`, and `alice-foo` from
sharing a host and inheriting each other's host-based permissions. Self-claimed
personas use the same identity encoding for ownership checks. Old ambiguous
account masks cannot safely be guessed into grants for a new encoded identity.

## Anonymous auth-split cloak (epoch-rotating)

When `[cloak] anon_epoch_secs` is non-zero (default `1209600` = 14 days), the cloak
engine **splits on authentication state**. An **unauthenticated** client
(`session.account() == null`) is cloaked with `cloakOpaqueEpochV4`:
`<32 hex>.e<epoch hex>.c<cadence hex>.opq4.<suffix>`. The **128-bit** token
comes from HMAC-SHA256 over a distinct v4 domain, canonical binary address and
family, epoch, cadence, and normalized suffix. IPv4-mapped IPv6 and the
equivalent native IPv4 address produce the same identity. Two consequences:

- the same address has a fresh keyed token across epochs; public provenance
  labels expose the period and epoch, not the address;
- the opaque single-token form leaks **no subnet co-membership** and no geo.

The epoch is `floor(wall_clock_seconds / anon_epoch_secs)`, computed by
`anonCloakEpoch` from `meshWallMs` (the reactor wall clock, not a per-node
monotonic clock). Every mesh node computes the same epoch for a given instant.
A connection that stays up across the boundary is recomputed on the maintenance
tick: local channels get CHGHOST, and peers get a fresh membership plus guest
presence so the new host is the one the rest of the mesh shows. A persona or an
account cloak is not rotated.

The period is aligned to the Unix epoch, not to the date a client connects.
Explicit existing `anon_epoch_secs = 86400` settings remain daily until changed;
changing the default alone does not update a deployed configuration.

### Automatic policy continuity

New v4 masks carry their own provenance. On a normal visible-host miss, the
policy matcher derives the candidate's cloak under the rule's original epoch
and cadence, using the trusted address already held by the daemon. This is
allocation-free and performs at most one derivation per configured current or
previous key. It does not retain an unbounded address history, scan epochs, or
rewrite policy stores every time a host changes.

Channel bans, exemptions, invite exceptions, quiets, IRCX ACCESS, SACCESS,
AKICK, and WARD use this context. Original nick and ident restrictions, rule
precedence, expiry, issuer, and deletion semantics remain intact. A wildcard in
the token can retain historical semantics when the epoch and cadence labels
are literal. A wildcard over those labels remains ordinary visible-host glob
matching; it does not authorize an unbounded epoch search.

Remote speech matching uses a matching secured oper-info roster entry bound to
the exact origin node, prefix, and account. Peers without the required private
roster information cannot provide historical matching through this seam.
No extra address data is sent to ordinary clients by this mechanism.

Continuity requires the relevant key and suffix. Older unlabeled v2/v3 opaque
tokens do not encode their cadence or epoch and cannot be reconstructed
indefinitely. Existing WARD compatibility checks are a bounded grace mechanism,
not a migration guarantee for arbitrary old masks. Audit legacy rules before a
release that changes public format or the configured cadence.

Address rules remain tied to an address; they cannot identify an anonymous
person who moves to an unrelated IP. Authenticated account rules follow the
account across addresses. Account/persona host matching retains its own scope.
Historical moderation matching also means rotation does not promise anonymity
from authorized moderation or erase correlation through a nick or an observed
CHGHOST.

If cloaking fails while a key is configured, the visible host is
`hidden.opq.<suffix>`. It is never the raw address and never a reverse name.

Operators and the user themselves also see a 320 `ban cloak <hierarchical>`
line. That host is the stable v2 hierarchical cloak (subnet tokens and
`a<asn>.<cc>`). WARD matches it, the current and previous v3 public tokens, and
the v2 64-bit opaque tokens, so a subnet hostmask and a ban written against the
previous public cloak still hit. None of those alternate hosts is the host
other users see.

**Logged-in clients are unaffected.** The auth-split branch in `applyVisibleHost`
fires only when `account() == null`; an authenticated client falls through to its stable,
moderatable account/hierarchical cloak and keeps subnet-bannability. The
trade-off is deliberate: moderation across unrelated addresses still requires
**account bans + registration friction**. Set `anon_epoch_secs = 0` to disable rotation and keep anonymous clients
on the stable hierarchical cloak (pre-2026-07 behavior). Because
`anon_epoch_secs` defaults to 14 days, anonymous clients switch from the
hierarchical `.ip` cloak to the opaque `.opq4` epoch cloak on upgrade unless the
operator sets it to `0`.

## Rotatable cloak key

The cloak key is derived at boot from `[cloak] secret` by **argon2id**, not a
bare `SHA256(secret)` ([src/main.zig:491](../../src/main.zig),
[deriveKey in src/crypto/argon2_kdf.zig:130](../../src/crypto/argon2_kdf.zig)).
The secret is stretched with the memory-hard KDF (64 MiB / t=2 / p=1,
`default_params`) under a fixed domain-separation salt
`onyx/cloak-key/argon2id/v1` (`cloak_key_salt`). The whole cloak security model
rests on key secrecy — the IPv4 input space is fully enumerable — so a
low-entropy operator passphrase must not be offline-brute-forceable: SHA-256
costs one hash per guess, argon2id costs ~64 MiB + t iterations per guess.
Derivation is **deterministic** (fixed salt), so cloaked hosts stay stable across
restarts and identical mesh-wide. With no secret, the daemon generates a random
per-boot key so privacy is on by default. `[cloak] previous_secret` derives a
second key (through the same argon2id path) kept live for **ban continuity across
a rotation**.

A failure deriving an explicitly configured current or previous key aborts
startup. It must not silently replace the requested key with a random one or
discard the requested grace key. Empty or whitespace-only configured secrets
and invalid public suffixes are rejected during configuration parsing.

**One-time reshuffle on upgrade.** This argon2id KDF replaced the prior
`SHA256(secret)` derivation, so on the first boot after that upgrade every
client's cloak reshuffles once: the derived key changed. Pre-upgrade host/subnet
WARD bans on the old SHA-256 cloaks do **not** carry over — they were computed
under a key the daemon can no longer reproduce, so the `previous_secret` grace
window applies only to *future* rotations under this argon2id KDF, not to the
SHA-256 → argon2id transition itself ([src/main.zig:480](../../src/main.zig)).

New cloaks always use the primary key. But bans written under the old key
reference old host/mask tokens, so `enforceWard`
([src/daemon/server.zig](../../src/daemon/server.zig)) does a fallback: on a
primary-key miss it re-checks the **host and mask facets recomputed under the
previous key** (`prevKeyCloakHost` mirrors the IP-cloak branch of
`applyVisibleHost`, honoring opaque mode). Only the key-derived facets differ —
address, account, country, ASN, certfp, and realname are key-independent, so the
primary check already covered them. Account/loopback hosts do not change with
the key and are skipped. Drop `previous_secret` once the old bans age out.

## rDNS: live but decoupled

Reverse DNS is resolved (the resolver is
[src/daemon/rdns.zig](../../src/daemon/rdns.zig), wired as `config.rdns`) but
**never feeds the public cloak** — cloaking the rDNS name
would expose the ISP's registrable domain (`….comcast.net`). `applyVisibleHost`
therefore always cloaks the **IP itself**, not the resolved name. The
forward-confirmed rDNS name is surfaced only in the operator/self view: it is
folded into the free-form `RPL_WHOISSPECIAL` (320) line as `rDNS <name> · <geo>`
in the local WHOIS path. (The `cloakHostname` primitive — mask dynamic labels,
keep the registrable domain — exists in the engine but is not on the daemon's
visible-host path for this reason.)

## Cross-mesh operator view of real identity

A remote (cross-mesh) user's WHOIS historically showed only the cloaked host,
because the mesh roster never carried the deanonymized identity. It is now
propagated so oper **admins** get the same view they have for local users
(commit `caa9c78`).

- **Wire** — `real_host` and `certfp` are OPTIONAL trailing blocks #3/#4 on the
  membership event ([src/proto/membership_event.zig](../../src/proto/membership_event.zig),
  `max_real_host_len` / `max_certfp_len`), positional and count-disambiguated so
  an older peer that never negotiates them sees zero extra bytes.
- **Gating** — these fields are SENSITIVE, so they ride **only the secured leg**.
  `s2s_peer` advertises `cap_member_oper_info` **only when it holds a node
  signing key** — the same secured-link indicator as frame signing
  ([src/substrate/undertow/s2s_peer.zig](../../src/substrate/undertow/s2s_peer.zig),
  `caps |= cap_frame_signing | cap_member_oper_info`). `sendMembership` emits the
  fields only to a peer that negotiated the cap, else empty — a plaintext leg
  never carries them.
- **Storage** — `route_table` `MemberIdentity`/`Member` own `real_host`/`certfp`
  ([src/substrate/undertow/route_table.zig](../../src/substrate/undertow/route_table.zig)),
  duped on create and `replaceOwned` on LWW update; `recvMembership` threads the
  decoded fields into `applyMembership`.
- **Display** — `sendRemoteWhois` reveals the real IP (338), GeoIP/ASN (320,
  resolved locally from that IP), and certfp (276) **only to an operator
  requester**, and only when the fields actually propagated.

### WHOIS numerics — who sees what

Numerics are defined in [src/proto/numeric.zig](../../src/proto/numeric.zig).

| Numeric | Meaning | Local user WHOIS | Remote (mesh) user WHOIS |
| --- | --- | --- | --- |
| `338` `RPL_WHOISACTUALLY` | real host / IP | Oper or self | Oper requester + field propagated (secured leg) |
| `320` `RPL_WHOISSPECIAL` | rDNS and GeoIP/ASN (the literal address itself is on `338` only, never repeated here), oper/self `ban cloak`, and +R/+g message-restriction hints | rDNS, geo, and `ban cloak`: oper or self. +R/+g hints: any requester | rDNS, geo, and `ban cloak`: oper requester when the real IP propagated (geo and the ban cloak are computed locally). +R/+g hints are local-user only |
| `276` `RPL_WHOISCERTFP` | TLS client-cert fingerprint | Any requester (it is the value SASL EXTERNAL matches) | Oper requester + certfp propagated |

Note the asymmetry: locally, `276` is not oper-gated (a client's certfp is not
address-sensitive), but cross-mesh it rides the oper-info cap and is shown only
to opers — a regular user never sees a remote user's certfp. `320` is also not
only an identity line: the WHOIS builder emits additional public `320` lines for
local targets in +R (registered senders only) and +g (caller-ID accept list)
because those are message-delivery hints, not deanonymized host data.

## `[cloak]` configuration

Section parsed in
[src/daemon/config_format.zig](../../src/daemon/config_format.zig) (`Cloak`) and
wired in [src/main.zig](../../src/main.zig).

| Key | Type | Default | Effect |
| --- | --- | --- | --- |
| `secret` | string | random per-boot | Passphrase stretched to the 32-byte cloak key by **argon2id** (64 MiB / t=2 / p=1, fixed salt). Absent → random key (privacy still on; cloaks are not stable across restarts). |
| `previous_secret` | string | none | Prior secret (same argon2id path) kept live so WARD host/mask bans written under it keep matching during a rotation grace window. Drop once old bans age out. |
| `suffix` | string | `onyx` | Network-identifying tail: IP cloaks end in `.ip.<suffix>` / `.ip6.<suffix>`; hostname/account cloaks embed it. |
| `mode` | string | `hierarchical` | `hierarchical` = subnet-bannable tokens + `a<asn>.<cc>` labels; `opaque` = one 128-bit token, no subnet/geo leak, not subnet-bannable. |
| `account_cloak` | bool | `false` | Logged-in clients show the key-free `<account>.users.<suffix>`. Explicit VHOST personas still override. |
| `anon_epoch_secs` | integer (seconds) | `1209600` | Anonymous auth-split cadence (14 days). Non-zero → unauthenticated clients get the provenance-bearing 128-bit epoch cloak, including clients that stay connected across the boundary. `0` keeps the stable cloak. Explicit daily settings must be updated separately. |

Configured values must have the listed parser types. A malformed value is
rejected rather than treated as absent; an invalid secret therefore cannot
silently select a random per-boot key. Resolved `mode` accepts only `opaque`
or `hierarchical`. Missing environment/file references fail with a fixed field
name, without printing the configured value or private reference. Allocation
failure remains a separate error. Omitted settings retain their documented
defaults. The TOML parser represents bare date/time atoms as strings; this
validation follows those parser types rather than enforcing lexical TOML types.

**Mesh requirement.** Every mesh node MUST share one `[cloak] secret`. On a
meshed node with no shared secret, each node derives its own random per-boot key,
so cloaked hosts differ per node and change on restart — `*!*@<cloak>` and subnet
WARD bans neither federate across the mesh nor survive a restart.
`--check-config` **hard-errors** on this: `meshCloakSecretMissing`
([src/daemon/config_format.zig:829](../../src/daemon/config_format.zig)) is true
when the node is meshed (`[mesh] connect` set **or** `[listen] s2s` set) and
`[cloak] secret` is null, and `main.zig` refuses to boot
([src/main.zig:192](../../src/main.zig)).


## Public history and operator comparison

WHOWAS records the explicit visible host at nick change or departure, retaining
that historical public identity through later cloak rotations. Invalid or absent
visible storage uses a generic host and cannot fall back to the real address.
Account numerics retain their existing public-account meaning. Existing history
is local and is not currently transferred through process exec; older running
images retain their own behavior until upgraded.

For planned changes, operators can compare locally available configuration with
`onyx-server doctor <config> --peer-config <peer-config> [--json]`. The
[comparison guide](../ops/doctor-cloak-comparison-2026-10-27.md) explains the fixed
categories and their scope. Results describe those resolved configurations;
runtime observations remain unknown until separately measured.
