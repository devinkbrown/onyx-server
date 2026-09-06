# Halloy capability matrix (third-party interop)

*Audience: integrators and QA operators validating that a modern third-party IRC
client (Halloy) can use Onyx Server without the first-party Onyx web client.*

This matrix is the Era 2 **B11** interop surface: every Onyx Server CAP (and the
related non-CAP commands third-party clients care about) scored against what
**Halloy** actually requests and implements. Claims about Onyx Server are cited
to this tree; claims about Halloy are cited to the Halloy `main` tree at the
pinned commit below. Do not invent CAPs — if a name is missing from
`cap_specs`, it is not advertised.

Companion references:

- Live CAP registry: [protocol/caps.md](protocol/caps.md)
- Full IRCv3 status map: [ircv3.md](ircv3.md)
- ISUPPORT tokens: [protocol/isupport.md](protocol/isupport.md)
- Web Push / VAPID: [web-push.md](web-push.md)
- IRCX PROP/ACCESS: [ircx/README.md](ircx/README.md)
- First-party Onyx CAP filter: `/home/kain/onyx/src/lib/irc/client.ts` (`_wantedCaps`, current body at lines 1344-1357)

## Source pins

| Side | Authority | Pin |
|---|---|---|
| Onyx Server CAPs | `cap_specs` in `src/daemon/dispatch.zig:316-445` (`CapId` at `:243`) | this repository HEAD |
| Onyx Server SASL mechs | `writeSaslCapValue` at `src/daemon/dispatch.zig:1435-1445` | this repository HEAD |
| Onyx first-party REQ filter | `_wantedCaps` in `/home/kain/onyx/src/lib/irc/client.ts:1344-1357` | Onyx tree HEAD |
| Halloy REQ set | `Capability` + `Capabilities::create_requested` in [data/src/capabilities.rs](https://github.com/squidowl/halloy/blob/d97e05afcc49e036521cd013235d699c04569d17/data/src/capabilities.rs) | commit `d97e05afcc49e036521cd013235d699c04569d17` (2026-07-20) |
| Halloy marketing list | [README “IRCv3 Capabilities”](https://github.com/squidowl/halloy/blob/d97e05afcc49e036521cd013235d699c04569d17/README.md) | same commit; **REQ list above wins** when they disagree |
| Halloy release tag | GitHub release `2026.7.2` (2026-06-08) | use for operator install; CAP tokens re-verified against `main` |

Halloy’s own comment states the REQ enum is the non-exhaustive list of caps it
will request (`capabilities.rs` header on `Capability`). Features listed only
in the README (for example client-tag UX that rides on `message-tags`) are
called out as **passive** below.

## Status legend (third-party column)

| Status | Meaning for a non-Onyx client |
|---|---|
| **Green** | Onyx Server advertises; Halloy `CAP REQ`s (or fully uses via ISUPPORT/command). Safe interop floor. |
| **Passive** | Server offers; Halloy consumes the wire form without a dedicated CAP REQ (usually via `message-tags` or ISUPPORT). |
| **Partial** | Overlap exists but a mechanism, value, or UX path is incomplete on one side. |
| **Server-only** | Onyx Server offers; Halloy does not request or implement. Third-party clients must add support themselves. |
| **Vendor / first-party** | Onyx Server vendor CAP or proprietary command; Halloy ignores. Onyx web client may use it. |
| **Halloy-only** | Halloy requests; Onyx Server does **not** advertise. REQ is simply omitted from ACK (or NAKs only if batched with unknown tokens — Halloy requests known tokens individually). |
| **Config-gated** | Advertised only when operator config enables it. |

Onyx Server `CAP REQ` is atomic: unknown or unavailable tokens NAK the whole
request without partial mutation (`src/daemon/dispatch.zig` CAP REQ path;
[protocol/caps.md](protocol/caps.md)). Halloy builds REQ lists only from tokens
it recognized in CAP LS, so a Halloy-only token never appears in a REQ against
Onyx Server.

---

## 1. IRCv3 capability matrix

Columns:

- **Onyx Server** — advertised in live `cap_specs` (yes / gated / dual-name).
- **Halloy** — `REQ` = in `create_requested`; `passive` = used without REQ; `no` = not implemented as a CAP consumer.
- **Onyx web** — first-party filter in `_wantedCaps` (yes / no / conditional).
- **3P status** — third-party (Halloy-shaped) readiness on Onyx Server.

| CAP / feature | Onyx Server | Halloy | Onyx web | 3P status | Notes + evidence |
|---|---|---|---|---|---|
| `server-time` | yes | REQ | yes | **Green** | `dispatch.zig:317`; Halloy `create_requested` |
| `message-tags` | yes | REQ | yes | **Green** | `dispatch.zig:318`; unlocks TAGMSG + client-only tags |
| `echo-message` | yes | REQ | yes | **Green** | `dispatch.zig:319` |
| `sasl` | yes (value = live mechs) | REQ | conditional (password or client cert) | **Partial** | Server mechs richer than Halloy (see §2). `dispatch.zig:330`, `writeSaslCapValue:1435` |
| `multi-prefix` | yes | REQ | yes | **Green** | `dispatch.zig:331` |
| `userhost-in-names` | yes | REQ | yes | **Green** | `dispatch.zig:332` |
| `away-notify` | yes | REQ | yes | **Green** | `dispatch.zig:333` |
| `setname` | yes | REQ | yes | **Green** | `dispatch.zig:334` |
| `extended-join` | yes | REQ (after `account-notify`) | yes | **Green** | `dispatch.zig:335`; Halloy requires `account-notify` available |
| `invite-notify` | yes | REQ | yes | **Green** | `dispatch.zig:336` |
| `account-tag` | yes | **no** | yes | **Server-only** | Server: `dispatch.zig:337`. Halloy `Capability` enum has no `account-tag` entry — third-party clients will not see `account=` tags unless they REQ it |
| `account-notify` | yes | REQ | yes | **Green** | `dispatch.zig:396` |
| `chghost` | yes | REQ | yes | **Green** | `dispatch.zig:355` |
| `batch` | yes | REQ | yes | **Green** | `dispatch.zig:385`; required dependency for Halloy chathistory |
| `labeled-response` | yes | REQ | yes | **Green** | `dispatch.zig:415`; Onyx web now requests it (`client.ts` falls through to `return true`) |
| `cap-notify` | yes (static set; no NEW/DEL) | passive (README) | yes | **Passive** | `dispatch.zig:410`; CAP NEW/DEL never fire on the static set |
| `standard-replies` | yes | passive (parses `FAIL`) | yes | **Passive** | `dispatch.zig:407`; Halloy handles `Command::FAIL` without REQ |
| `bot` | yes | passive (README + ISUPPORT `BOT`) | **no** (`client.ts:1230`) | **Passive** | CAP at `dispatch.zig:386`; mode letter also via ISUPPORT |
| `extended-monitor` | yes | REQ | yes | **Green** | `dispatch.zig:392` |
| `no-implicit-names` | yes (dual) | REQ (prefers stable, else draft) | **no** (`client.ts:1206`) | **Green** | Same `CapId`; draft alias `dispatch.zig:361-362` |
| `draft/no-implicit-names` | yes (alias) | REQ fallback | no | **Green** | ACK echoes the requested token |
| `draft/chathistory` | yes | REQ (needs `batch`) | yes | **Green** | `dispatch.zig:373`; CHATHISTORY command is the Halloy history path — **no vendor bouncer required** |
| `draft/event-playback` | yes | REQ (needs batch + chathistory) | yes | **Green** | `dispatch.zig:381` |
| `draft/search` | yes | **no** | yes | **Server-only** | `dispatch.zig:377`; SEARCH is first-party / advanced clients |
| `draft/message-redaction` | yes | REQ | yes | **Green** | `dispatch.zig:378`; Halloy `redaction.rs` handles `REDACT` |
| `draft/message-editing` | yes | **no** | yes | **Server-only** | `dispatch.zig:379`; Halloy has no EDIT path in surveyed sources |
| `draft/read-marker` | yes | REQ | yes | **Green** | `dispatch.zig:380` |
| `draft/typing` | yes | passive (TAGMSG `+typing`) | yes | **Passive** | Cap `dispatch.zig:382`; Halloy reads `+typing` with `message-tags` |
| `draft/react` | yes | passive (`+draft/react`) | yes | **Passive** | Cap `dispatch.zig:383`; Halloy `reaction.rs` |
| `draft/reply` | yes | passive (`+draft/reply`) | yes | **Passive** | Cap `dispatch.zig:384` |
| `draft/channel-rename` | yes | **no** | yes | **Server-only** | `dispatch.zig:389` |
| `draft/account-registration` | yes (`custom-account-name`) | **no** | yes | **Server-only** | `dispatch.zig:403`; REGISTER/VERIFY still work as plain commands if a client sends them |
| `draft/metadata-2` | yes | REQ | yes | **Green** | `dispatch.zig:405`; Halloy keys: `display-name`, `avatar`, `pronouns`, `homepage`, `color`, `status` (`metadata.rs`) — server store accepts those keys (`metadata.zig` tests use `display-name`) |
| `draft/pre-away` | yes | **no** | yes | **Server-only** | `dispatch.zig:420` |
| `draft/channel-context` | yes | passive (README client-tag) | yes | **Passive** | Cap `dispatch.zig:424`; rides client-tag relay |
| `draft/multiline` | yes (`max-bytes=40000,max-lines=64` default) | REQ | yes | **Green** | `dispatch.zig:428`; Halloy parses limits |
| `draft/netsplit` | yes | **no** | yes | **Server-only** | `dispatch.zig:443`; useful with `batch` for mesh partitions |
| `draft/netjoin` | yes | **no** | yes | **Server-only** | `dispatch.zig:444` |
| `account-extban` | yes (`a`) | **no** (ISUPPORT aware) | yes | **Partial** | CAP `dispatch.zig:441`; Halloy parses ISUPPORT `ACCOUNTEXTBAN` |
| `utf8-only` | yes | passive via ISUPPORT `UTF8ONLY` | yes | **Green** | CAP `dispatch.zig:442`; Halloy `isupport.rs` `UTF8ONLY` |
| `sts` | **config-gated** (`requires_policy`) | **no** | **no** (NAK risk; `client.ts:1201`) | **Config-gated** | Omitted unless STS policy configured (`dispatch.zig:436`) |
| `onyx/session-sync` | yes (vendor) | **no** | yes | **Vendor / first-party** | `dispatch.zig:340`; sibling-device DM mirror |
| `onyx/bouncer` | yes (vendor) | **no** | yes | **Vendor / first-party** | `dispatch.zig:344`; auto-rewind on join — Halloy uses `draft/chathistory` instead |
| `onyx/topics` | yes (vendor) | **no** | yes | **Vendor / first-party** | `dispatch.zig:348` |
| `onyx/e2ee` | yes (vendor) | **no** | yes | **Vendor / first-party** | `dispatch.zig:352`; E2EE control-plane tags |
| `soju.im/bouncer-networks` | **not advertised** | REQ | no | **Halloy-only** | Halloy soju multi-network; not an Onyx Server CAP |
| `draft/whoami` | **not advertised** | REQ | no | **Halloy-only** | Halloy optional; absent from `cap_specs` |
| `soju.im/filehost` | **not a CAP here** | ISUPPORT consumer | no | **Halloy-only** | Halloy reads `soju.im/FILEHOST` ISUPPORT (`isupport.rs`); Onyx Server does not emit it |
| `msgid` (not a CAP) | server tags with `message-tags` | passive | yes | **Green** | IRCv3 message-ids; Halloy README lists it; requires `message-tags` recipients |
| Monitor (not a CAP) | ISUPPORT `MONITOR` | yes | yes | **Green** | Halloy README + ISUPPORT; Onyx Server `protocol_inventory` / limits |
| WHOX (not a CAP) | ISUPPORT `WHOX` | yes | yes | **Green** | `protocol_inventory.zig`; Halloy `isupport.rs` |
| network-icon (not a CAP) | ISUPPORT `NETWORKICON` when configured | yes (README) | yes | **Config-gated** | `server.zig` `NETWORKICON=` when `[network] icon_url` set |

### CAP count summary (Onyx Server `cap_specs`)

Advertised names (including the `no-implicit-names` dual spelling): **45** name strings over **44** `CapId` values (`sts` policy-gated). Halloy explicitly REQs **22** of those names (counting one of the no-implicit-names spellings). The remainder are passive, server-only, vendor, or config-gated as above.

---

## 2. SASL mechanisms

| Mechanism | Onyx Server advertises when configured | Halloy | Onyx web | 3P status |
|---|---|---|---|---|
| `PLAIN` | yes | yes (`Sasl::Plain`) | yes | **Green** |
| `EXTERNAL` | yes (TLS client cert) | yes (`Sasl::External`) | yes (client cert path) | **Green** |
| `SCRAM-SHA-256` | yes | **no** | yes | **Server-only** (Halloy must use PLAIN/EXTERNAL) |
| `SCRAM-SHA-512` | yes | **no** | yes | **Server-only** |
| `SCRAM-SHA-512-PLUS` | yes (needs TLS exporter) | **no** | partial | **Server-only** |
| `SESSION-TOKEN` | yes (`sst_…` durable re-auth) | **no** | yes | **Vendor / first-party** |
| `OAUTHBEARER` | yes when wired | **no** | optional | **Server-only** |
| `ANONYMOUS` | yes when allowed | **no** | rare | **Server-only** |

Evidence: server `writeSaslCapValue` (`dispatch.zig:1435-1445`); Halloy
`data/src/config/server.rs` `Sasl` enum is only `Plain` and `External` (pinned
Halloy tree). Unconfigured checkers fail closed — a mech is omitted from CAP
value rather than advertised empty.

**Operator note for Halloy users:** configure Halloy SASL as `PLAIN` (account +
password) or `EXTERNAL` (client certificate). Do not expect SCRAM from Halloy
against Onyx Server today.

---

## 3. Non-CAP protocol surfaces (commands & discovery)

These are **not** IRCv3 capabilities. Third-party readiness is still part of
the B11 matrix because product claims (“Halloy can join, history, react/reply”)
depend on them.

| Surface | Onyx Server | Halloy | Onyx web | 3P status | Evidence |
|---|---|---|---|---|---|
| `CHATHISTORY` command | yes (`draft/chathistory`) | yes | yes | **Green** | Server `handle` path + `proto/chathistory_*.zig`; Halloy client CHATHISTORY usage |
| ISUPPORT `CHATHISTORY=<n>` | yes (limits path) | yes | yes | **Green** | `src/proto/isupport.zig` (`CHATHISTORY`); Halloy `isupport.rs` |
| `MARKREAD` | yes (`draft/read-marker`) | yes | yes | **Green** | Cap + command |
| `REDACT` | yes | yes | yes | **Green** | Halloy `redaction.rs` |
| `EDIT` | yes | **no** | yes | **Server-only** | Cap `draft/message-editing` |
| `SEARCH` | yes | **no** | yes | **Server-only** | Cap `draft/search` |
| `METADATA` GET/SET/LIST/CLEAR | yes | yes | yes | **Green** | Cap `draft/metadata-2` |
| `SESSION` / `SESSIONTOKEN` | yes | **no** | yes | **Vendor / first-party** | `modules/accounts.zig` `SESSION_spec`; multi-attach resume — not Halloy |
| `E2EEKEY` | yes | **no** | yes | **Vendor / first-party** | `E2EEKEY_spec` in `modules/accounts.zig:148` |
| `KEYTRANS` | yes | **no** | yes | **Vendor / first-party** | `KEYTRANS_spec` in `modules/accounts.zig:147` |
| `WEBPUSH` + ISUPPORT `VAPID` | yes when `[webpush] enabled` | **no** | yes | **Config-gated / first-party** | [web-push.md](web-push.md); no `draft/webpush` CAP in `cap_specs` — command + `VAPID=` token only |
| `MEDIA` + `EVENT … MEDIA` | yes (feature-gated) | **no** | yes | **Vendor / first-party** | [commands/media.md](commands/media.md); Cadence control plane |
| IRCX `PROP` | yes | **no** | yes | **Server-only** (third-party IRCv3 clients use `METADATA`) | [commands/ircx.md](commands/ircx.md); unified store in `proto/metadata.zig` |
| IRCX `ACCESS` | yes | **no** | optional | **Server-only** | `proto/ircx_access_store.zig`; channel ACL beyond `+b` |
| IRCX `EVENT` (generic spine) | yes | **no** | yes | **Vendor / first-party** | `modules/ircx.zig` registers `EVENT` |
| ISUPPORT `IRCX` | yes (bare token first) | **no** special-case | yes | **Passive** | `protocol_inventory.zig:70` — Halloy ignores; IRCX clients probe |
| ISUPPORT `PREFIX=(YQqov)*!.@+` | yes | yes (generic PREFIX) | yes | **Green** | Exotic prefixes; clients must learn from 005, not hardcode `@+` |
| WebSocket `text.ircv3.net` | yes | yes (Halloy WS support) | yes (prefers `onyx.irc-media.v1`) | **Green** | [ircv3.md](ircv3.md) WebSocket section |
| WebSocket `onyx.irc-media.v1` | yes | **no** | yes | **Vendor / first-party** | Media datagrams; Halloy stays on text IRC |

---

## 4. Practical third-party outcomes

### What Halloy gets “for free” on a stock Onyx Server

With TLS (or WSS), SASL PLAIN or EXTERNAL, and default caps:

1. Register / identify via SASL PLAIN or EXTERNAL.
2. Join channels; see multi-prefix names and userhosts.
3. Live chat with `server-time`, `echo-message`, `msgid` (via message-tags), typing/react/reply tags.
4. Scrollback via **`CHATHISTORY`** (`draft/chathistory` + `batch`) — **without** `onyx/bouncer`.
5. Read markers, redaction, multiline, metadata avatars/display-names.
6. Standard FAIL surfaces and UTF-8-only policy.

This is the intentional open-wire floor: vendor caps enhance Onyx web, they do
not gate basic modern IRC.

### What Halloy does **not** get (expected)

| Gap | Why |
|---|---|
| Multi-device session resume (`SESSION RESUME` / MTOKEN) | Proprietary session attachment; use SASL + CHATHISTORY instead |
| Automatic bouncer rewind (`onyx/bouncer`) | Halloy issues explicit CHATHISTORY |
| E2EE DMs / `onyx/e2ee` / `E2EEKEY` | First-party crypto control plane |
| Voice/video (`MEDIA` / Cadence) | First-party media stack |
| Browser Web Push | `WEBPUSH` + VAPID; desktop Halloy uses its own notifications |
| SCRAM SASL | Halloy config only PLAIN/EXTERNAL |
| Message editing (`EDIT`) | No Halloy implementation in surveyed tree |
| Server-side `SEARCH` | No Halloy implementation in surveyed tree |
| Account tags on every line | Halloy does not REQ `account-tag` |
| soju bouncer-networks / filehost | soju-specific; not offered by Onyx Server |

### Onyx web vs Halloy (first-party delta)

Onyx web (`_wantedCaps`) requests nearly every offered CAP except `tls`, `sts`,
`no-implicit-names`, `draft/file-upload`, and `bot`. It additionally depends on
vendor caps `onyx/session-sync`, `onyx/bouncer`, `onyx/topics`, and `onyx/e2ee`
when advertised. Halloy never requests vendor caps and prefers
`no-implicit-names` (Onyx web deliberately does not).

---

## 5. QA checklist (manual CAP matrix against a live node)

Run from any IRCv3-capable probe (or Halloy with logging). Replace host/port.

```text
# 1. CAP LS — every name in §1 "Onyx Server = yes" must appear (sts only if configured)
CAP LS 302

# 2. Halloy-shaped REQ (atomic; all names must be known to this server)
CAP REQ :message-tags server-time batch labeled-response echo-message multi-prefix
CAP REQ :userhost-in-names away-notify setname account-notify extended-join invite-notify
CAP REQ :chghost extended-monitor draft/chathistory draft/event-playback draft/read-marker
CAP REQ :draft/message-redaction draft/multiline draft/metadata-2 sasl

# 3. SASL PLAIN then CAP END, NICK/USER as usual
AUTHENTICATE PLAIN
… payload …
CAP END

# 4. History without vendor bouncer
CHATHISTORY LATEST #channel * 50

# 5. Confirm vendor caps are optional (must still work if never REQ'd)
#    onyx/session-sync, onyx/bouncer, onyx/topics, onyx/e2ee
```

Pass criteria for Era 2 B11 “green on Era 2 set”:

- [ ] CAP LS lists the Green rows in §1
- [ ] Halloy (or the REQ list above) ACKs without NAK
- [ ] CHATHISTORY returns a `chathistory` BATCH (with `batch`) or plain replay
- [ ] TAGMSG `+draft/react` / `+draft/reply` / `+typing` visible to a `message-tags` peer
- [ ] No dependency on `onyx/*` caps for join + history + basic react/reply

---

## 6. Maintenance

When either side changes:

1. Re-read `cap_specs` (`dispatch.zig`) — add/remove rows; never leave a ghost CAP.
2. Re-fetch Halloy `data/src/capabilities.rs` `create_requested` and update the pin commit in **Source pins**.
3. Keep [protocol/caps.md](protocol/caps.md) as the exhaustive server table; this file is the **interop view**, not a second registry.
4. If Halloy gains `account-tag`, `draft/message-editing`, or SCRAM, flip the matching §1/§2 status to Green and drop the gap row.

**Not verified in this pass:** a live Halloy GUI session against production
nodes (matrix is source-derived). Wire CAP LS against a running daemon before
calling a release “B11 closed.” Automated CAP-matrix CI remains a follow-up.
