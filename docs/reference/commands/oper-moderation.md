# Operator and moderation commands

*Operator authority, network bans, force actions, and server-to-server link control.*

The `oper.security` module registers the core oper and moderation commands (`src/daemon/modules/oper_security.zig:143`). Most are registry-gated with `.access = .oper`; `OPER` and `STATS` are the command-table exceptions, while `USERIP` is oper-gated and then refined by `oper_spy` (`src/daemon/modules/oper_security.zig:149`, `src/daemon/modules/oper_security.zig:173`, `src/daemon/modules/oper_security.zig:176`). Registry denial emits `ERR_NOPRIVILEGES 481` (`src/daemon/server.zig:8408`, `src/daemon/server.zig:8416`). Handlers check fine-grained operator privileges with `requirePriv` (`src/daemon/server.zig:26953`).

## OPER

- Syntax: `OPER <ignored...>`
- Description: Password `OPER` is disabled. Onyx Server grants operator status only from authenticated accounts with configured oper bindings via `elevateOperFromAccount`.
- Privileges: Registered client; never grants by command password.
- Parameters: Ignored by handler.
- Replies: None on success because the command always fails.
- Errors: `ERR_NOOPERHOST 491`.
- Example: `OPER name password`
- Sources: `src/daemon/modules/oper_security.zig:149`, `src/daemon/server.zig:22220`, `src/daemon/server.zig:22225`

## REHASH

- Syntax: `REHASH`
- Description: Reloads configuration/state through the server rehash handler.
- Privileges: Oper plus `server_rehash` privilege.
- Parameters: None.
- Replies: `RPL_REHASHING 382` and/or server notices from handler.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `REHASH`
- Sources: `src/daemon/modules/oper_security.zig:150`, `src/daemon/server.zig:27927`

## GRANT

- Syntax: `GRANT <account> <class> [priv,priv,...]`
- Description: Gives a registered account operator authority network-wide. Mints a
  signed grant recorded locally, propagated to secured S2S peers, and honored on
  the account's next SASL login; already-connected sessions are elevated
  immediately. Privileges come from the class preset (`admin`/`netadmin`/`sa` →
  full, incl. `oper_grant`; any other class → a standard operator set) or an
  explicit comma-separated privilege-name list. Persisted across restart when
  `[oper] grants_path` is set.
- Privileges: Oper holding the `oper_grant` privilege.
- Parameters: Target account; class label; optional privilege list.
- Replies: Server notice confirming the grant.
- Errors: `ERR_NOPRIVILEGES 481`, `ERR_NEEDMOREPARAMS 461`; notice on unknown account/privilege.
- Example: `GRANT alice netadmin`
- Sources: `src/daemon/modules/oper_security.zig:151`, `src/daemon/server.zig:22640`

## REVOKE

- Syntax: `REVOKE <account>`
- Description: Removes a runtime operator grant network-wide. A zero-privilege
  tombstone supersedes the grant (propagated to peers, honored on next login) and
  connected sessions are de-elevated immediately (`MODE -o` + notice). Configured
  `[[opers]]` accounts are not revocable this way (edit config + `REHASH`).
- Privileges: Oper holding the `oper_grant` privilege.
- Parameters: Target account.
- Replies: Server notice confirming the revocation.
- Errors: `ERR_NOPRIVILEGES 481`, `ERR_NEEDMOREPARAMS 461`.
- Example: `REVOKE alice`
- Sources: `src/daemon/modules/oper_security.zig:152`, `src/daemon/server.zig:22677`

## GRANTS

- Syntax: `GRANTS`
- Description: Lists the live runtime operator grants (account, class, issuer node). Tombstoned (revoked) accounts are omitted.
- Privileges: Oper.
- Parameters: None.
- Replies: Server notices, one per active grant, then an end marker.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `GRANTS`
- Sources: `src/daemon/modules/oper_security.zig:153`, `src/daemon/server.zig:22702`

## AUDIT

- Syntax: `AUDIT [JSON] [oper] [count] | AUDIT PROOF [JSON] <proof-id>`
- Description: Lists recent privileged actions from the bounded oper audit ring. Signed records and signed Event Spine moderation notices include `proof=<id>` for covered actions including `KILL`, `JUPE`, native `WARD ADD`/`WARD DEL`, `SHUN`, `UNSHUN`, `CONNECT`, `SQUIT`, `REDACT`, IRCX `ACCESS` add/delete/clear mutations, and FORCE* channel actions. `AUDIT JSON` streams stable audit objects, and `AUDIT PROOF JSON <proof-id>` returns the stored ProofMark policy fields, reason hash, public key, detached signature, and a `valid=true|false` verification result.
- Privileges: Oper holding the `audit_read` privilege.
- Parameters: Optional oper filter and count for record listing; ProofMark id for proof inspection.
- Replies: Event Spine lines: `:<server> EVENT <oper> AUDIT ...`.
- Errors: `ERR_NOPRIVILEGES 481`; usage or missing proof reports are server notices.
- Example: `AUDIT PROOF JSON 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`
- Sources: `src/daemon/modules/oper_security.zig:178`, `src/daemon/server.zig:27536`

## SESSIONS

- Syntax: `SESSIONS [oper|user] [tls|clear] [nick-glob] [account=<glob>] [ip=<glob>] [sort=connected] [limit=N]`
- Description: Read-only operator connection inventory across all reactor shards. It excludes S2S links, reports registered clients with nick/account/IP/TLS/operator state, applies optional filters, sorts by connection age, and caps output with `limit=` (default bounded by the handler).
- Privileges: Oper.
- Replies: `RPL_TRACEUSER 205` rows followed by `RPL_ENDOFTRACE 262`; invalid filters and over-large result sets are server notices.
- Errors: `ERR_NOPRIVILEGES 481` and invalid-filter/too-many-match notices.
- Example: `SESSIONS tls account=alice sort=connected limit=20`
- Sources: `src/daemon/modules/oper_security.zig:179`, `src/daemon/server.zig:29116` (`handleSessions`), `src/daemon/svc_sessionview.zig`

## KILL

- Syntax: `KILL <nick> [:reason]`
- Description: Disconnects a local target nick, or relays the kill across the mesh to the node that owns the nick, and publishes the operator action.
- Privileges: Oper plus `client_kill` privilege.
- Parameters: Target nick; optional reason.
- Replies: Local target receives a `KILL` line and close/error path; remote targets produce a relay notice to the operator; the oper action is published.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHNICK 401`, `ERR_NOPRIVILEGES 481`.
- Example: `KILL badnick :abuse`
- Sources: `src/daemon/modules/oper_security.zig:154`, `src/daemon/server.zig:13599`

## CLOSE

- Syntax: `CLOSE`
- Description: Closes unregistered/unknown clients and reports counts.
- Privileges: Oper plus `client_moderate` privilege.
- Parameters: None.
- Replies: Server notice reporting the number of unregistered connections closed.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `CLOSE`
- Sources: `src/daemon/modules/oper_security.zig:155`, `src/daemon/server.zig:13572`

## DRAIN

- Syntax: `DRAIN [OFF]`
- Description: Toggles listener drain state so new client accepts are refused while existing links stay up. With no argument, or any argument other than `OFF`, drain is enabled; `OFF` disables it.
- Privileges: Oper plus `server_admin` privilege.
- Parameters: Optional `OFF`.
- Replies: Server `NOTICE` status.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `DRAIN`
- Sources: `src/daemon/modules/oper_security.zig:156`, `src/daemon/server.zig:13562`

## UNREJECT

- Syntax: `UNREJECT <ip>`
- Description: Clears an IP from the connection reject/throttle table.
- Privileges: Oper.
- Parameters: IP string.
- Replies: Server notice.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`.
- Example: `UNREJECT 203.0.113.10`
- Sources: `src/daemon/modules/oper_security.zig:157`, `src/daemon/server.zig:13541`

## WARD

- Syntax: `WARD ADD <match> <pattern> [scope] [action] [secs] [:reason] | WARD DEL <match> <pattern> | WARD LIST [match] | WARD TEST <match> <value>`
- Description: Unified Warden network-ban registry. A Ward is `Match x Scope x Action`: match facets are `address`, `host`, `mask`, `account`, `realname`, `certfp`, `country`, and `asn`; scopes are `node` or `mesh`; actions are `refuse`, `expel`, `quarantine`, or `require_auth`. The canonical English surface is `WARD`; the live registry also carries compatibility aliases `KLINE`, `DLINE`, and `XLINE` into Warden, with no separate `GLINE`, `ZLINE`, or `QLINE` commands registered.
- Privileges: Oper plus `client_moderate` privilege.
- Parameters: Subcommand-specific Warden axes and optional duration/reason.
- Replies: Server notices and oper events. `WARD ADD` and `WARD DEL` oper events include `proof=<id>` when the node has a signing identity. `WARD TEST` reports match/no-match by notice.
- Errors: `ERR_NOPRIVILEGES 481`; usage and validation failures are server notices.
- Example: `WARD ADD address 203.0.113.0/24 mesh refuse 3600 :abuse`
- Sources: `src/daemon/modules/oper_security.zig:158`, `src/daemon/modules/oper_security.zig:160`, `src/daemon/modules/oper_security.zig:161`, `src/daemon/modules/oper_security.zig:162`, `src/daemon/server.zig:15902`, `src/daemon/warden.zig:26`

## KLINE / DLINE / XLINE

- Syntax: `KLINE [ADD|DEL|REMOVE] <pattern> [secs] [:reason] | DLINE [ADD|DEL|REMOVE] <pattern> [secs] [:reason] | XLINE [ADD|DEL|REMOVE] <pattern> [secs] [:reason]`
- Description: Compatibility aliases into Warden. `KLINE` creates/removes a node-scope `mask` ward with default action `expel`; `DLINE` maps to an `address` ward with default action `refuse`; `XLINE` maps to a `realname` ward with default action `expel`.
- Privileges: Oper plus `client_moderate` privilege.
- Parameters: Optional add/remove subcommand, pattern, optional seconds, optional reason.
- Replies: WARD oper events/notices from the shared add/delete path.
- Errors: `ERR_NOPRIVILEGES 481`; usage and validation failures are server notices.
- Example: `KLINE ADD bad!*@* 3600 :abuse`
- Sources: `src/daemon/modules/oper_security.zig:54`, `src/daemon/modules/oper_security.zig:58`, `src/daemon/modules/oper_security.zig:62`, `src/daemon/modules/oper_security.zig:160`, `src/daemon/server.zig:16002`

## SPAMTRAP

- Syntax: `SPAMTRAP ADD <NICK|CHAN> <target> | SPAMTRAP DEL <NICK|CHAN> <target> | SPAMTRAP LIST`
- Description: Operator-designated spam-trap (honeypot) registry. A trap nick or channel is one a legitimate user has no reason to contact. A non-operator that PRIVMSGs a trap nick or JOINs a trap channel trips the trap, which raises a one-shot `FLOOD` Event Spine alert and flags the offender for follow-up (for example, with `WARD`). The hot path is lock-free when no traps are configured. `LIST` reports trap and offender counts.
- Privileges: Oper plus `client_moderate` privilege.
- Parameters: Subcommand, target kind (`NICK`/`CHAN`), and target.
- Replies: Server notice + oper event; offenders are flagged in the registry.
- Errors: `ERR_NOPRIVILEGES 481`; usage and add/remove failures are server notices.
- Example: `SPAMTRAP ADD CHAN #freenudes`
- Sources: `src/daemon/modules/oper_security.zig:159`, `src/daemon/server.zig:27681`, `src/daemon/spamtrap.zig`

## SHUN

- Syntax: `SHUN [<nick|ip|mask> [secs] [:reason]]`
- Description: Adds a gag/shun restriction through the `handleShun` path.
- Privileges: Oper plus `client_moderate` privilege.
- Parameters: Optional target mask, optional duration in seconds, optional reason.
- Replies: Server notice/oper event with `proof=<id>` when the node has a signing identity.
- Errors: `ERR_NOPRIVILEGES 481`; handler validation notices. Bare `SHUN` lists active shuns.
- Example: `SHUN badnick :flood`
- Sources: `src/daemon/modules/oper_security.zig:163`, `src/daemon/server.zig:15688`

## UNSHUN

- Syntax: `UNSHUN <nick|ip|mask>`
- Description: Clears a gag/shun restriction through the same handler with `adding = false`.
- Privileges: Oper plus `client_moderate` privilege.
- Parameters: Target.
- Replies: Server notice/oper event with `proof=<id>` when the node has a signing identity.
- Errors: `ERR_NOPRIVILEGES 481`; handler validation notices.
- Example: `UNSHUN badnick`
- Sources: `src/daemon/modules/oper_security.zig:164`, `src/daemon/server.zig:15688`

## GLOBAL

- Syntax: `GLOBAL [<mask>|#channel] :<message>`
- Description: Sends a server global notice to connected users, optionally scoped to a hostmask or channel audience.
- Privileges: Oper plus `server_admin` privilege.
- Parameters: Optional audience selector; message text.
- Replies: Broadcast notice.
- Errors: `ERR_NOPRIVILEGES 481`; usage/format failures are server notices.
- Example: `GLOBAL :maintenance soon`
- Sources: `src/daemon/modules/oper_security.zig:165`, `src/daemon/server.zig:15751`

## OPERMOTD

- Syntax: `OPERMOTD [SET :text]`
- Description: Shows the operator MOTD, or replaces it when `SET` is used.
- Privileges: Oper to read; `OPERMOTD SET` also requires `server_admin`.
- Parameters: Optional `SET` and text.
- Replies: Operator MOTD numerics or server notices.
- Errors: `ERR_NOPRIVILEGES 481`; no-oper-MOTD numeric/notice if unset.
- Example: `OPERMOTD`
- Sources: `src/daemon/modules/oper_security.zig:166`, `src/daemon/server.zig:15303`

## DIE

- Syntax: `DIE`
- Description: Publishes a critical oper action and clears the reactor run flag. Requires shutdown privilege.
- Privileges: Oper plus `server_shutdown` privilege.
- Parameters: None.
- Replies: Oper event; no numeric success reply.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `DIE`
- Sources: `src/daemon/modules/oper_security.zig:167`, `src/daemon/server.zig:16127`

## RESTART

- Syntax: `RESTART`
- Description: Same handler as `DIE`, but checks `server_restart` privilege and labels the action as `RESTART`.
- Privileges: Oper plus `server_restart` privilege.
- Parameters: None.
- Replies: Oper event; no numeric success reply.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `RESTART`
- Sources: `src/daemon/modules/oper_security.zig:168`, `src/daemon/server.zig:16127`

## CONNECT

- Syntax: `CONNECT <host> <port>`
- Description: Opens an outbound server-to-server link, creating either a secured S2S initiator or plaintext S2S link and submitting an async connect.
- Privileges: Oper plus `mesh_admin` privilege.
- Parameters: Host and TCP port.
- Replies: Oper event with `proof=<id>` when the node has a signing identity, plus server notice such as `CONNECT initiated` or `CONNECT initiated (secured)`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`, notices for illegal port, invalid host, full table, or socket failure.
- Example: `CONNECT 203.0.113.20 6667`
- Sources: `src/daemon/modules/oper_security.zig:169`, `src/daemon/server.zig:17164`

## SQUIT

- Syntax: `SQUIT <server> [:reason]`
- Description: Finds an established S2S peer by remote server name and closes it.
- Privileges: Oper plus `mesh_admin` privilege.
- Parameters: Server name; reason is currently not used by the handler.
- Replies: Oper event with `proof=<id>` when the node has a signing identity, plus `SQUIT complete` notice.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHSERVER 402`, `ERR_NOPRIVILEGES 481`.
- Example: `SQUIT peer.example :maintenance`
- Sources: `src/daemon/modules/oper_security.zig:170`, `src/daemon/server.zig:17314`

## TESTLINE

- Syntax: `TESTLINE <mask>`
- Description: Probes the target against Warden address, mask, and host facets. This is a Warden probe, not a legacy K/D-line command.
- Privileges: Oper.
- Parameters: Mask/IP/host token.
- Replies: `RPL_TESTLINE 725` or `RPL_NOTESTLINE 726`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`.
- Example: `TESTLINE 203.0.113.10`
- Sources: `src/daemon/modules/oper_security.zig:174`, `src/daemon/server.zig:17388`

## TESTMASK

- Syntax: `TESTMASK <mask>`
- Description: Counts registered clients whose `nick!user@host` matches a glob.
- Privileges: Oper.
- Parameters: Hostmask glob.
- Replies: `RPL_TESTMASK 727`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`.
- Example: `TESTMASK *!*@*.example`
- Sources: `src/daemon/modules/oper_security.zig:175`, `src/daemon/server.zig:17407`

## USERIP

- Syntax: `USERIP <nick>...`
- Description: Returns up to five nick entries with oper/away flags and IP-style host data.
- Privileges: Oper plus `oper_spy` privilege.
- Parameters: Nick list.
- Replies: Numeric `340` line from `userip.writeUseripReply`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`.
- Example: `USERIP alice bob`
- Sources: `src/daemon/modules/oper_security.zig:176`, `src/daemon/server.zig:16085`

## DEBUG

- Syntax: `DEBUG`
- Description: Dumps the flight recorder as server notices.
- Privileges: Oper plus `audit_read` privilege.
- Parameters: None.
- Replies: Server notices and final `End of DEBUG flight recorder`.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `DEBUG`
- Sources: `src/daemon/modules/oper_security.zig:177`, `src/daemon/server.zig:17374`

## GEOIP

- Syntax: `GEOIP <ip>`
- Description: Looks up an IP in the configured MaxMind database and reports country, location, ASN/network, and proxy/hosting flags when present.
- Privileges: Oper plus `oper_spy` privilege.
- Parameters: IPv4 or IPv6 literal.
- Replies: Server notices.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`; notices for invalid IP, missing database, read error, or no data.
- Example: `GEOIP 8.8.8.8`
- Sources: `src/daemon/modules/feature_misc.zig:65`, `src/daemon/server.zig:19312`

## CLONES

- Syntax: `CLONES`
- Description: Reports connection clusters sharing an exact IP or /24-/64-style network prefix, annotated with GeoIP tags when available.
- Privileges: Oper.
- Parameters: None.
- Replies: Server notices.
- Errors: `ERR_NOPRIVILEGES 481`; `CLONES: scan failed` notice on scan failure.
- Example: `CLONES`
- Sources: `src/daemon/modules/services_ext.zig:65`, `src/daemon/server.zig:19408`

## RESV

- Syntax: `RESV [ADD] <#pattern> <duration-ms> :reason | RESV DEL <#pattern> | RESV LIST | RESV SWEEP`
- Description: Adds, removes, lists, or sweeps channel-name reservations. Reserved names are refused at `JOIN` for non-opers with `ERR_UNAVAILRESOURCE 437`.
- Privileges: Oper.
- Parameters: Parsed by `svc_resv.parseServerCommand`.
- Replies: Server notices.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`; join enforcement emits `ERR_UNAVAILRESOURCE 437`.
- Example: `RESV #help* 3600000 :reserved`
- Sources: `src/daemon/modules/services_ext.zig:53`, `src/daemon/server.zig:18525`, `src/daemon/svc_resv.zig:224`

## UNRESV

- Syntax: `UNRESV <#pattern>`
- Description: Alias command path into the same reservation parser, removing a reservation.
- Privileges: Oper.
- Parameters: Channel glob pattern.
- Replies: Server notice.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`.
- Example: `UNRESV #help*`
- Sources: `src/daemon/modules/services_ext.zig:54`, `src/daemon/server.zig:18525`, `src/daemon/svc_resv.zig:227`

## SACCESS

- Syntax: `SACCESS ADD <DENY|GAG|GRANT|NOCHANNEL|NONICK|HOLDNICK> <mask> [duration] [:reason] | SACCESS <DEL|DELETE> <type> <mask> | SACCESS LIST [type] | SACCESS CLEAR [type]`
- Description: Server-level IRCX access policy. `DENY`, `GAG`, and `GRANT` match hostmasks; `NOCHANNEL` forbids channel-name masks; `NONICK` blocks nick masks; `HOLDNICK` reserves nick masks while allowing operators and `GRANT`-exempt clients to use them. This is the nick-side forbid system, alongside channel `RESV` and server-name `JUPE`.
- Privileges: Oper plus `service_admin` privilege.
- Parameters: Subcommand, entry type, mask, optional duration, optional reason.
- Replies: IRCX access numerics `RPL_ACCESSADD 801`, `RPL_ACCESSDELETE 802`, `RPL_ACCESSSTART 803`, `RPL_ACCESSENTRY 804`, and `RPL_ACCESSEND 805`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`, `ERR_TOOMANYACCESSES 916`. Enforcement can emit `ERR_ERRONEUSNICKNAME 432` for `NONICK`/`HOLDNICK` and `ERR_UNAVAILRESOURCE 437` for `NOCHANNEL`.
- Example: `SACCESS ADD HOLDNICK Staff-* 0 :staff namespace`
- Sources: `src/daemon/modules/ircx.zig:67`, `src/proto/ircx_saccess.zig:73`, `src/proto/ircx_saccess.zig:306`, `src/daemon/server.zig:19495`, `src/daemon/server.zig:19548`

## JUPE

- Syntax: `JUPE [ADD] <server-glob> <duration-ms> :reason | JUPE DEL <server-glob> | JUPE LIST | JUPE SWEEP`
- Description: Forbids a server-name glob from linking into the mesh. A matching peer is refused when it reaches the link-established transition; an already-linked peer that becomes juped is dropped on its next drive.
- Privileges: Oper.
- Parameters: Server-name glob, duration in milliseconds, reason; or list/remove/sweep subcommand.
- Replies: Server notices; `JUPE ADD` publishes an oper event with `proof=<id>` when the node has a signing identity.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`.
- Example: `JUPE evil.example.net 0 :rogue server`
- Sources: `src/daemon/modules/services_ext.zig:56`, `src/daemon/server.zig:18591`, `src/daemon/svc_jupe.zig:247`

## UNJUPE

- Syntax: `UNJUPE <server-glob>`
- Description: Alias command path into the same server-name jupe parser, removing a jupe entry.
- Privileges: Oper.
- Parameters: Server-name glob.
- Replies: Server notice.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`.
- Example: `UNJUPE evil.example.net`
- Sources: `src/daemon/modules/services_ext.zig:57`, `src/daemon/server.zig:18591`, `src/daemon/svc_jupe.zig:255`

## FORCEOP

- Syntax: `FORCEOP <#channel> <nick>`
- Description: Forces channel operator mode on a target nick. Successful actions publish an oper Event Spine notice with `proof=<id>` when the node has a signing identity.
- Privileges: Oper.
- Parameters: Channel and nick.
- Replies: `MODE` broadcast or server notice for no-op.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOSUCHNICK 401`, `ERR_USERNOTINCHANNEL 441`, `ERR_NOPRIVILEGES 481`.
- Example: `FORCEOP #zig alice`
- Sources: `src/daemon/modules/services_ext.zig:58`, `src/daemon/server.zig:18687`, `src/daemon/server.zig:18756`

## FORCEDEOP

- Syntax: `FORCEDEOP <#channel> <nick>`
- Description: Forces removal of channel operator mode from a target nick. Successful actions publish an oper Event Spine notice with `proof=<id>` when the node has a signing identity.
- Privileges: Oper.
- Parameters: Channel and nick.
- Replies: `MODE` broadcast or server notice for no-op.
- Errors: Same as `FORCEOP`.
- Example: `FORCEDEOP #zig alice`
- Sources: `src/daemon/modules/services_ext.zig:59`, `src/daemon/server.zig:18687`, `src/daemon/server.zig:18756`

## FORCEJOIN

- Syntax: `FORCEJOIN <#channel> <nick>`
- Description: Applies `JOIN` to the target user's live connection. Successful actions publish an oper Event Spine notice with `proof=<id>` when the node has a signing identity.
- Privileges: Oper.
- Parameters: Channel and nick.
- Replies: Normal join replies to target; `Force action applied` notice to oper.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHNICK 401`, join errors, `ERR_NOPRIVILEGES 481`.
- Example: `FORCEJOIN #zig alice`
- Sources: `src/daemon/modules/services_ext.zig:60`, `src/daemon/server.zig:18687`, `src/daemon/server.zig:18737`

## FORCEPART

- Syntax: `FORCEPART <#channel> <nick> [:reason]`
- Description: Parts a target user from a channel with an optional reason. Successful actions publish an oper Event Spine notice with `proof=<id>` when the node has a signing identity.
- Privileges: Oper.
- Parameters: Channel, nick, optional reason.
- Replies: `PART` broadcast; `Force action applied` notice.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOSUCHNICK 401`, `ERR_NOPRIVILEGES 481`.
- Example: `FORCEPART #zig alice :cleanup`
- Sources: `src/daemon/modules/services_ext.zig:61`, `src/daemon/server.zig:18687`, `src/daemon/server.zig:18744`

## FORCETOPIC

- Syntax: `FORCETOPIC <#channel> :<topic>`
- Description: Sets a channel topic as the server and broadcasts it. Successful actions publish an oper Event Spine notice with `proof=<id>` when the node has a signing identity.
- Privileges: Oper.
- Parameters: Channel and topic.
- Replies: `TOPIC` broadcast.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOPRIVILEGES 481`.
- Example: `FORCETOPIC #zig :new topic`
- Sources: `src/daemon/modules/services_ext.zig:62`, `src/daemon/server.zig:18687`, `src/daemon/server.zig:18780`
