# Feature and interface index

This is the source-backed entry point for the 0.9.0 feature surface, reconciled
on 2026-11-03. It links canonical detailed references instead of maintaining a
second implementation manual. The [release audit](../audit/release-and-test-speed-2026-11-03.md)
separately records accepted Linux fleet behavior. Source availability, configured
enablement, client support and live acceptance are distinct claims.

Host administration is indexed separately in the [server CLI reference](server-cli.md);
IRC commands, host modes and the Armor executable are different interfaces.

## Features by user task

| Task | Supported surface and material limits | Details and source |
|---|---|---|
| Connect and authenticate | IRC registration, implicit TLS, CAP, configured SASL mechanisms, certificate binding, account tokens, 2FA/passkeys/OAuth. STARTTLS is not a daemon command. | [Connection](commands/connection.md), [accounts](commands/accounts-services.md), [credentials](credential-domains.md); `dispatch.zig`, `services.zig`. |
| Reuse a session | Reusable logical groups with physical attachments, local exact restore, signed replicas/leases, portable legacy reclaim and composite exact-restore credentials. Composite issuer/destination rules can require REDIRECT. | [Session contract](../design/session-resume-anywhere-blueprint.md), [credential domains](credential-domains.md); `sessions.zig`, live SESSION handlers. |
| Chat and retrieve history | Channel/DM text and tags, replies/reactions, edit/redact, bounded search/history, read markers, pins, bouncer rewind. Accepted MESSAGE_V2 uses stable signed identity/time and transactional publication. Custody is Helix-preserved RAM, not a crash WAL. | [Messaging](commands/messaging.md), [MESSAGE_V2 contract](../design/message-v2-exact-once.md); `message_relay_v2.zig`, replay/outbox/spool owners. |
| Manage channels and privacy | Modes, membership, invitations, bans/quiet/access, IRCX properties, channel services, slowmode and content policy. Per-command rank/account/TLS gates apply. | [Channels](commands/channels.md), [modes](protocol/modes.md), [IRCX](ircx/README.md); `world.zig`, module handlers. |
| Establish trusted mesh links | Undertow CRDT projection, Mooring authenticated encrypted transport, pinned direct neighbors, signed origins, bounded repair, presence and route reports. A TCP slot is not an established secured link. | [Mesh architecture](../architecture/mesh-s2s.md), [security](../architecture/mesh-security.md), [mesh commands](commands/mesh-ops.md). |
| Operate and moderate | Account-derived operator grants, Warden, SACCESS, policy generations, ProofMark/AUDIT, typed EVENT/OBSERVE, bounded replay and diagnostics. | [Moderation](commands/oper-moderation.md), [automation/policy](commands/automation-policy.md), [Event Spine](../architecture/event-spine.md), [v2 contract](../design/event-spine-mesh-v2.md). |
| Use voice/video/screen media | MEDIA control, native Cadence UDP, selected WebRTC SRTP/DTLS, browser binary-WS relay, client-held E2EE control and transcode-free native/WebRTC bridge. Endpoint keys and physical identity authorize routing; browser E2EE is not bridged to plaintext UDP legs. | [MEDIA](commands/media.md), [media architecture](../architecture/03-media.md), [native authentication](native-media-mac.md). |
| Record with consent | Opt-in bounded packet journals, asynchronous write/rotation/manifest, room consent policy, retention and quotas. Active/retired recording custody can block Helix. No movie transcoding promise. | [MEDIA](commands/media.md), [config](config.md#media); `media_record.zig`, live recorder ownership. |
| Automate and integrate | Incoming WEBHOOK, outbound OUTHOOK, scoped BOTGRANT/BOTCMD, deferred messages/modes, opt-in UNFURL, appeals/challenges/holds/quarantine. Some source flags lack TOML projection and remain off by default. | [Automation/policy](commands/automation-policy.md), [WEBHOOK](commands/accounts-services.md#webhook), [fantasy weather/news](commands/fantasy-bot.md). |
| Deliver browser notifications | Account-scoped Web Push subscription management, VAPID and encrypted payloads for offline DMs. Requires configured outbound delivery and account store. | [Web Push](web-push.md), `[webpush]`; `daemon/webpush.zig`, `crypto/webpush.zig`. |
| Inspect keys, certificates and TLS from a host | Armor CLI includes certificate/key/CSR/digest/random/chain/OCSP/CRL tools and offline verification. Its `s_client` CLI network path remains unsupported; the TLS library has separate socketless-client consumers. | [Armor CLI](armor-cli.md), [crypto architecture](../architecture/crypto.md); `src/cli/armor_main.zig`. |
| Extend the daemon | Compile-time validated modules with per-server lifecycle/reload and gated hooks; bounded OroWasm control-plane interpreter and effective grant/budget introspection. | [Module system](../architecture/MODULE-SYSTEM.md), [OroWasm](../architecture/04-upgrade-wasm.md#orowasm-host-and-dispatch); module/runtime and WASM host sources. |
| Upgrade and run reliably | Guarded compatible Helix adoption, fail-closed mandatory state, TERM/INT stop fencing, validated OpenRC/systemd kits, one-node-at-a-time cold rollback when required. | [Upgrade](../architecture/04-upgrade-wasm.md), [runbook](../RUNBOOK.md), [services](../guide/service-management.md). |
| Observe and maintain data | Metrics, status/channel JSON, stats, backups, tracing, embedded WAL/snapshots, account and moderation persistence. Public feed permissions depend on the deployment's explicit umask/path policy. | [Observability](../architecture/observability-stats.md), [config](config.md), [runtime paths](../ops/onyx-server-paths.md). |

## Complete enabled command inventory

The enabled module declarations currently contain **170 unique registered names
including the `MODLIST` alias**. The lower connection table adds `PASS`, `USER`,
`CAP`, `AUTHENTICATE` and `PING` beyond those names, for **175 distinct command
spellings across these two tables**. `NICK`, `PONG` and `QUIT` occur in both layers.
Special preregistration routing (for example IRCX discovery or CHALLENGE answers)
is controlled by the server and is not inferred from registry presence.

| Enabled module/source | Commands and aliases | Detailed family reference |
|---|---|---|
| [query.info](../../src/daemon/modules/query_info.zig) | `VERSION`, `TIME`, `ADMIN`, `INFO`, `DIRECTORY`, `MOTD`, `LUSERS`, `USERS`, `LINKS`, `MAP`, `CHANSTATS` | [Reference](commands/informational.md) |
| [channel.ops](../../src/daemon/modules/channel_ops.zig) | `JOIN`, `PART`, `NAMES`, `MODE`, `KICK`, `INVITE`, `TOPIC`, `KNOCK`, `CREATE`, `RENAME`, `CHANBADWORDS` | [Reference](commands/channels.md) |
| [messaging](../../src/daemon/modules/messaging.zig) | `PRIVMSG`, `NOTICE`, `TAGMSG`, `REDACT`, `EDIT`, `CHATHISTORY`, `SEARCH`, `MARKREAD`, `PINS`, `METADATA`, `MONITOR`, `SILENCE` | [Reference](commands/messaging.md) |
| [accounts](../../src/daemon/modules/accounts.zig) | `REGISTER`, `VERIFY`, `IDENTIFY`, `TOTP`, `RECOVERYCODES`, `LOGOUT`, `DROP`, `SETPASS`, `RESETPASS`, `SUCCESSOR`, `ACCOUNTINFO`, `ACCOUNT`, `SASLINFO`, `ACCOUNTSET`, `GHOST`, `RECOVER`, `RELEASE`, `CHANNEL`, `CS`, `SESSION`, `SESSIONTOKEN`, `CERTADD`, `WEBAUTHN`, `KEYTRANS`, `E2EEKEY`, `E2EEGROUP`, `IDENTITY`, `CERTLIST`, `CERTDEL`, `RECOGNIZE`, `LISTCHANS` | [Reference](commands/accounts-services.md) |
| [ircx](../../src/daemon/modules/ircx.zig) | `IRCX`, `ISIRCX`, `DATA`, `REQUEST`, `REPLY`, `WHISPER`, `PROP`, `ACCESS`, `SACCESS`, `AUTH`, `EVENT`, `MODEX`, `LISTX` | [Reference](commands/ircx.md) |
| [oper.security](../../src/daemon/modules/oper_security.zig) | `OPER`, `REHASH`, `GRANT`, `REVOKE`, `GRANTS`, `KILL`, `CLOSE`, `DRAIN`, `UNREJECT`, `WARD`, `SPAMTRAP`, `KLINE`, `DLINE`, `XLINE`, `SHUN`, `UNSHUN`, `ABUSE`, `GLOBAL`, `OPERMOTD`, `DIE`, `RESTART`, `CONNECT`, `SQUIT`, `TRACE`, `ETRACE`, `STATS`, `TESTLINE`, `TESTMASK`, `USERIP`, `DEBUG`, `AUDIT`, `SESSIONS`, `MESH`, `NETSTAT`, `ROUTE`, `NETHEALTH` | [Reference](commands/oper-moderation.md) |
| [user.query](../../src/daemon/modules/user_query.zig) | `ISON`, `USERHOST`, `WHOIS`, `LIST`, `WHO`, `WHOX`, `WHOWAS`, `AWAY`, `SETNAME`, `NICK`, `QUIT`, `ACCEPT`, `HELP`, `HELPOP`, `AUTOJOIN`, `GROUP`, `WELCOME` | [Reference](commands/queries.md) |
| [feature.misc](../../src/daemon/modules/feature_misc.zig) | `VHOST`, `PRIVS`, `FILTER`, `POLICY`, `OUTHOOK`, `BOTGRANT`, `DEFER`, `UNFURL`, `APPEAL`, `CHALLENGE`, `HOLD`, `QUARANTINE`, `BOTCMD`, `MEDIA`, `MEMO`, `WEBPUSH`, `ACTIVITY`, `GEOIP`, `SUMMON`, `PONG` | [Reference](commands/automation-policy.md) |
| [diag.introspect](../../src/daemon/modules/introspect.zig) | `MODULES`, `COMMANDS`, `OROWASM`, `MODLIST` | [Reference](commands/informational.md) |
| [ops.upgrade](../../src/daemon/modules/upgrade.zig) | `UPGRADE` | [Reference](commands/mesh-ops.md) |
| [services.ext](../../src/daemon/modules/services_ext.zig) | `RESV`, `UNRESV`, `JUPE`, `UNJUPE`, `FORCEOP`, `FORCEDEOP`, `FORCEJOIN`, `FORCEPART`, `FORCETOPIC`, `CLEAR`, `TEMPMODE`, `CLONES`, `SEEN` | [Reference](commands/oper-moderation.md) |
| [webhook](../../src/daemon/modules/webhook.zig) | `WEBHOOK` | [Reference](commands/accounts-services.md) |

Every name above is covered by the [command index](commands/_index.md). Feature,
registration, IRCX, module-health, account and operator checks can hide or reject
an otherwise declared command. `COMMANDS [name]` reports the effective surface
for the caller; it is preferable to guessing enablement from this static list.
Fantasy `!weather`/`!forecast`/`!news` commands are message-body integrations,
not additional registry verbs. Host CLI subcommands are documented separately
in the [runbook](../RUNBOOK.md) and [development guide](../development.md).

## Configuration coverage

`config_format.zig` defines the live `Config`, typed defaults and `parseToml`;
`config_boot.zig`/`main.zig` own runtime wiring. The same-named extraction
directory is not the live parser entry; inspect actual imports before using it
as authority. Start from the
[reference TOML](../../etc/onyx-server.reference.toml), then use the
[key-by-key configuration reference](config.md). Internal `server.Config` fields
are not automatically operator-settable TOML options.

| Area | Accepted section families | Detailed reference |
|---|---|---|
| Identity and presentation | `[node]`, `[network]`, `[motd]`, `[admin]` | [Config](config.md#node) |
| Listeners and transport security | `[listen]`, `[tls]`, `[[tls.sni]]`, `[[tls.ech_keys]]`, `[sts]`, `[acme]`, `[ocsp]` | [Config](config.md#listen) |
| Secured mesh and guest presence | `[mesh]`, `[mesh.routing]`, `[mesh.gossip]`, `[mesh.ripple]`, `[mesh.link]`, `[guest_presence]` | [Config](config.md#mesh) |
| Admission and resource limits | `[limits]`, `[class.<name>]`, `[io]`, `[reputation]`, `[dnsbl]`, `[cloak]` | [Config](config.md#limits) |
| Accounts, sessions and messaging | `[accounts]`, `[sasl]`, `[sessions]`, `[bouncer]`, `[ircv3]`, `[history.search]`, `[webauthn]`, `[e2ee]`, `[filter]`, `[mail]` | [Config](config.md#accounts) |
| Operator/module policy | `[oper]`, `[oper.ocg2]`, `[[opers]]`, `[[oper_groups]]`, `[wasm]` | [Config](config.md#oper) |
| Media and social features | `[media]`, `[media.sfu]`, `[media.pins]`, `[media.reactions]`, `[weather]`, `[news]`, `[geo]`, `[geoip]`, `[webpush]`, `[webhook]` | [Config](config.md#media) |
| Persistence and observability | `[storage]`, `[stats]`, `[backup]`, `[metrics]`, `[logging]`, `[trace]` | [Config](config.md#storage) |

Parser support alone does not mean a setting changes a live owner during REHASH;
consult the config reference's wiring limits. `--check-config` validates the
actual supplied file with the new binary and daemon user before deployment.

## Complete client CAP names

The current immutable [live metadata table](../../src/proto/live_cap_metadata.zig)
contains **47 names over 46 CapId values**. The two no-implicit-names spellings
share one ID. SASL and STS advertisements depend on session/runtime policy.

`server-time`, `message-tags`, `echo-message`, `sasl`, `multi-prefix`, `userhost-in-names`, `away-notify`, `setname`, `extended-join`, `invite-notify`, `account-tag`, `onyx/session-sync`, `onyx/bouncer`, `onyx/topics`, `onyx/e2ee`, `chghost`, `no-implicit-names`, `draft/no-implicit-names`, `draft/chathistory`, `draft/search`, `draft/message-redaction`, `draft/message-editing`, `draft/read-marker`, `draft/event-playback`, `draft/typing`, `draft/react`, `draft/reply`, `batch`, `bot`, `draft/channel-rename`, `extended-monitor`, `account-notify`, `draft/account-registration`, `draft/metadata-2`, `standard-replies`, `cap-notify`, `labeled-response`, `draft/pre-away`, `draft/channel-context`, `draft/multiline`, `sts`, `account-extban`, `utf8-only`, `draft/netsplit`, `draft/netjoin`, `onyx/2fa`, `onyx/privacy`.

[CAP behavior](protocol/caps.md) and [SASL/tag detail](ircv3-capabilities.md)
describe values, atomic request handling and recipient gates. [ISUPPORT](protocol/isupport.md),
[modes](protocol/modes.md), [numerics](protocol/numerics.md) and the
[IRCv3 coverage map](ircv3.md) describe adjacent interfaces. Client interoperability requires a version-specific negotiated-surface test;
this source index does not certify an external client release.

## Development and release evidence

Follow [development](../development.md), [testing](../guide/testing.md),
[source-module ownership](../architecture/source-modules.md) and the
[documentation maintenance rules](../MAINTENANCE.md). Narrow focused tests and
cached filters accelerate iteration; only complete source-bound full-suite
receipts establish a ship gate. External interoperability checks and native
platform acceptance have separate scopes. The production revision and test-only
revision need not be the same; the [release audit](../audit/release-and-test-speed-2026-11-03.md)
records both rather than implying that every later documentation commit was deployed.
