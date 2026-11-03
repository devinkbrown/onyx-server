# Onyx Server ISUPPORT (005)

*The `RPL_ISUPPORT` tokens Onyx Server advertises, their defaults, and their configuration override paths.*

`src/proto/protocol_inventory.zig` is the source of truth for static `RPL_ISUPPORT` tokens (`src/proto/protocol_inventory.zig`). At boot, `main.zig` installs the configured network name, builds config-driven ISUPPORT tokens, and stores runtime limits before serving clients (`src/main.zig`).

The live server emits `RPL_ISUPPORT` with `protocol_inventory.currentIsupport()` and trailing text `are supported by this server` (`src/daemon/server.zig`). The pre-registration welcome burst emits the same current token list (`src/daemon/dispatch.zig`).

## Token table

| Token | Default Value | Meaning | Config / Runtime Notes | Evidence |
| --- | --- | --- | --- | --- |
| `IRCX` | present | Advertises IRCX support. | Bare token, advertised **first** (as IRCX servers do) so a passive client that never sends `IRCX` still detects it. | `src/proto/protocol_inventory.zig` |
| `NETWORK` | `Onyx` | Advertised network name. | Default is `network_name` (`Onyx`); operators can override via `[network] name`, installed by `setNetworkName` and rewritten by `buildIsupportTokens`. | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig`, `src/main.zig` |
| `CHANTYPES` | `#&` | Channel name prefixes accepted/advertised. | Static token. | `src/proto/protocol_inventory.zig` |
| `NICKLEN` | `64` | Maximum nick length in bytes. | Config-overridable via `[limits]`; pre-registration NICK enforcement reads `currentLimits().nicklen`. | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig`, `src/daemon/dispatch.zig` |
| `TOPICLEN` | `390` | Maximum topic bytes. | Config-overridable via `[limits]`; TOPIC truncates to configured `topiclen` on UTF-8 boundary. | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig` |
| `AWAYLEN` | `256` | Maximum AWAY message bytes. | Config-overridable via `[limits]` in `buildIsupportTokens`. | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig` |
| `KICKLEN` | `307` | Maximum KICK comment bytes. | Config-overridable via `[limits]`; KICK truncation is documented in handler comments. | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig` |
| `CHANNELLEN` | `64` | Maximum channel name length. | Config-overridable via `[limits]` in `buildIsupportTokens`. | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig` |
| `MAXLIST` | `beIZ:100` | Per-channel cap on list modes `+b`, `+e`, `+I`, `+Z`. | Config-overridable via `[limits]`; `World.max_list_entries` enforces the cap. | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig`, `src/daemon/world.zig` |
| `CHANLIMIT` | `#&:50` | Maximum joined channels by prefix class. | Config-overridable via `[limits]`; a nonzero `[class.*] max_channels` overrides the enforced cap for matching connections, allowing class-specific tightening. JOIN emits `ERR_TOOMANYCHANNELS` when exceeded. | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig` |
| `MAXTARGETS` | `4` | Maximum message targets per PRIVMSG/NOTICE command. | Config-overridable via `[limits]`; a nonzero `[class.*] max_targets` overrides the enforced fan-out cap for matching connections, allowing class-specific tightening. Excess emits `ERR_TOOMANYTARGETS`. | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig` |
| `KEYLEN` | `64` | Maximum channel-key (`+k`) length in bytes. | Config-overridable via `[limits] keylen`; `buildIsupportTokens` swaps the value and the MODE `+k` handler enforces it. | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig` |
| `MONITOR` | `128` | Maximum MONITOR targets. | Config-overridable via `[limits]`; a nonzero `[class.*] monitor` overrides the add cap for matching connections, allowing class-specific tightening. MONITOR handler maps list-full to `ERR_MONLISTFULL`. | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig` |
| `SILENCE` | `32` | Maximum SILENCE masks. | Config-overridable via `[limits]`; a nonzero `[class.*] silence` overrides the owner cap for matching connections, allowing class-specific tightening. SILENCE query emits 271/272. | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig` |
| `CASEMAPPING` | `ascii` | Case-folding policy for identifiers. | World maps use ASCII case-insensitive contexts for nicks/channels. | `src/proto/protocol_inventory.zig`, `src/daemon/world.zig` |
| `PREFIX` | `(YQqov)*!.@+` | Member status modes and their prefix characters. | Network-operator `Y`/`*` is derived from oper override privilege and ranks above founder; founder `Q`/`!` is Onyx Server-native and ranks above owner. | `src/proto/protocol_inventory.zig`, `src/daemon/chanmode.zig` |
| `CHANMODES` | `beIZ,k,lfj,imntsCTNgSMWOAphuadErzxwVUFDcBK` | Four channel-mode classes: list, param-always, param-on-set, flag. | Static token from `chanmodes_token`. `W` (news-wire), `O` (oper-only), `A` (admin-only), `V` (NOCOMICDATA), `U` (OPMODERATE), `F` (FREETARGET), and `D` (DISFORWARD) are live flag modes; see `modes.md`. | `src/proto/protocol_inventory.zig` (`chanmodes_token`) |
| `STATUSMSG` | `!.@+` | Allowed status-target prefixes for channel messages. | Server maps `!`, `.`, `@`, `+` to minimum delivery ranks. | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig` |
| `CHATHISTORY` | `64` | CHATHISTORY batch limit. | Static token. | `src/proto/protocol_inventory.zig` (`isupport_tokens`) |
| `ELIST` | `CMNTU` | Extended LIST condition support. | Static token. | `src/proto/protocol_inventory.zig` (`isupport_tokens`) |
| `SAFELIST` | present | LIST is flood-safe. | Static token. | `src/proto/protocol_inventory.zig` (`isupport_tokens`) |
| `EXCEPTS` | `e` | Ban-exception list mode letter. | Static token. | `src/proto/protocol_inventory.zig` (`isupport_tokens`) |
| `INVEX` | `I` | Invite-exception list mode letter. | Static token. | `src/proto/protocol_inventory.zig` (`isupport_tokens`) |
| `MAXPROP` / `MAXACCESS` | present | IRCX PROP/ACCESS list caps. | Static tokens. | `src/proto/protocol_inventory.zig` (`isupport_tokens`) |
| `MAXCODEPAGE` / `MAXLANGUAGE` | `0` | IRCX codepage/language caps (none). | Static tokens. | `src/proto/protocol_inventory.zig` (`isupport_tokens`) |
| `CALLERID` | `g` | Caller-id user mode letter. | Static token; see `modes.md`. | `src/proto/protocol_inventory.zig` |
| `DEAF` | `D` | Deaf user mode letter. | Static token; see `modes.md`. | `src/proto/protocol_inventory.zig` |
| `BOT` | `B` | Bot user mode letter. | Mirrors user mode `+B` and IRCv3 bot support. | `src/proto/protocol_inventory.zig`, `src/proto/usermode.zig` |
| `EXTBAN` | `$,acgmrz` | Extended-ban namespace and supported extban types. | World list matching parses `$` entries for account, channel, country, mute, realname, secure-transport, and negation contexts; malformed `$` masks are rejected before storage. | `src/proto/protocol_inventory.zig`, `src/proto/extban.zig`, `src/daemon/world.zig` |
| `WHOX` | present | WHOX extended WHO replies are supported. | WHOX uses `RPL_WHOSPCRPL` 354 and `RPL_ENDOFWHO` 315. | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig` |
| `UTF8ONLY` | present | Clients must send UTF-8 message bodies. | Invalid PRIVMSG body gets `FAIL <command> INVALID_UTF8`; NOTICE stays silent. | `src/proto/protocol_inventory.zig`, `src/daemon/server.zig` |
| `VAPID` | *(absent)* | base64url ES256 VAPID public key for browser [Web Push](../web-push.md). | **Config-driven, not static** — advertised only when `[webpush] enabled = true`; the value is the node's VAPID public key, so a browser can subscribe without an extra command round trip. | `src/daemon/server.zig` |

## Override path

`buildIsupportTokens` copies the static token list and rewrites `NETWORK`, `TOPICLEN`, `AWAYLEN`, `KICKLEN`, `NICKLEN`, `CHANNELLEN`, `MAXLIST`, `CHANLIMIT`, `MAXTARGETS`, `KEYLEN`, `MONITOR`, and `SILENCE` from `Config` (`src/daemon/server.zig`). Tokens not matched by those prefixes are borrowed directly from the static inventory (`src/daemon/server.zig`).

The advertised `CHANLIMIT`, `MAXTARGETS`, `MONITOR`, and `SILENCE` values are the global `[limits]` values. After registration, matching `[class.*]` policy can override the enforced cap for that connection through `max_channels`, `max_targets`, `monitor`, and `silence`; `0` inherits the advertised global (`src/daemon/conn_class.zig`, `src/daemon/config_format.zig`).

`protocol_inventory.currentIsupport()` returns the config-built override when installed, otherwise the static array (`src/proto/protocol_inventory.zig`).
