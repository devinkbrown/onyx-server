# IRCX evolution roadmap (2026-10-15)

Research note for Onyx Server. Execution order from 2026-10-16 is
`docs/dev/execution-roadmap-2026-10-16.md`. IRCX here means
`draft-pfenning-irc-extensions-04` (Dalen Abraham, Microsoft, June 1998;
expired individual draft, never an RFC) plus the parts Onyx Server has
already grown past it. This file invents the next feature set. It does
not deploy, push, or reopen a closed cut.

Primary text: <https://www.ietf.org/archive/id/draft-pfenning-irc-extensions-04.txt>.
Local extraction: `docs/reference/ircx/ircx-draft-pfenning-04.md`.
Live command index: `docs/reference/ircx/README.md`.
The smaller upgrade map that already landed Help, CREATE oid replies,
LAG, LISTX limits, and ONJOIN/ONPART is
`docs/dev/upgrade-roadmap-2026-10-15.md`. This document sits above that
map. Where they disagree, this document wins on security.

## 1. What the 1998 draft actually is

IRCX is a client-to-server extension of RFC 1459. The abstract's own
sentence is: only client-server interactions are defined. The draft does
not define a server-to-server protocol, a replay rule, or a mesh. A chat
network is "one or more servers linked together" (section 4), and
services "communicate with the core server over an extended IRC
connection" (section 2). Onyx Server must not import a second services
protocol to satisfy that sentence. Services stay real server commands.

The draft adds six ideas that still matter:

| Idea | Draft location | What it gives a person |
| --- | --- | --- |
| Named access levels | section 4.1 | Sysop manager, sysop, owner, host, member, user |
| Object prefixes | section 4.2, table 4 | `#` `&` `%#` `%&` `'` `^` `0`+8 hex `$` |
| `ACCESS` masks | section 5.1 | GRANT, DENY, HOST, OWNER, VOICE, with `*` and `?` and a timeout |
| `AUTH` as SASL | section 5.2 | `I` / `S` / `*` before `NICK`/`USER`, challenge-response preferred |
| `PROP` | section 5.12 and 8.2 | One string store for topic, keys, on-join text, language, account |
| `CREATE` / `OID` | sections 5.3, 6.3, 8.2.1 | Create-if-absent, then a short id the client can store |

It also adds `DATA`/`REQUEST`/`REPLY`, `EVENT`, `LISTX`, `WHISPER`,
`KNOCK`, `REDIRECT`, `CLONE`, and the mode list in section 8.1
(`+h` hidden, `+u` knock, `+f` noformat, `+w` nowhisper, `+x` auditorium,
`+r` registered, `+z` service, `+a` authonly, `+d` cloneable, `+e` clone).

Section 10 is the whole security model, and it is short. Two claims:

1. `IRCX` / `ISIRCX` advertise authentication mechanisms. A middleman
   can strip that list down to a cleartext password method. The draft's
   mitigation is: use only challenge-response mechanisms.
2. Administration commands are cleartext. Integrity and confidentiality
   require SSL or IPsec. How the stream is established is out of scope.

Wikipedia's IRCX summary matches this scope: SASL, channel properties,
extra privilege levels, operator levels, and Unicode names, published as
expired drafts 00, 01, 02, and 04, never an RFC.
<https://en.wikipedia.org/wiki/IRCX>

Two IRCv3 commands cover the same stated purpose under different names.
Published SASL (`AUTHENTICATE`, capability `sasl`) is connect-time
authentication; the 1998 command is `AUTH` and had to be the first IRCX
message, before `USER` and `NICK`. Ratified `labeled-response` correlates
one request with its reply; the 31 January 1997 draft had an optional
bracketed reply prefix, and the June 1998 text dropped it. No IRCv3
specification cites IRCX. The match is shared purpose.

These do not replace IRCX objects. `account-tag` names the account the
other client is logged into. The IRCX `ACCOUNT` property is a
security-account string of at most 31 characters. Message tags are a
framing layer. They do not carry `DATA` / `REQUEST` / `REPLY`. The 1998
text has no chat-history command. IRCv3 `CHATHISTORY` is still
`draft/chathistory`; only the chathistory batch type is described as
stable playback. Onyx Server already advertises `CHATHISTORY`. This map
does not treat that advertisement as an IRCX feature.

IRCX remains the room model: named modes, access lists, properties,
whisper, and typed data. It is not a second authentication stack.

## 2. What Onyx Server already changed, on purpose

These stay. A later slice must not "correct" them back to 1998.

| Choice | Why it stays |
| --- | --- |
| No pseudo-clients | NickServ-style bots are a second trust domain. Account commands are server commands. |
| No `TACCESS` / `BTPROP` / `OPFORCE` / `SVSJOIN` | Undertow already replicates access and properties. Those verbs were a C-era mesh. |
| No Comic Chat `DATA` avatar | Untyped blobs with a private layout. |
| `WALLOPS` is `EVENT BROADCAST` | One operator announce path. |
| MODEX replies are 826/827 | Kept off the draft's 806/807 event band. The live doc that still says 806/807 for MODEX is stale. |
| LISTX 812 layout is members, created-ms, topic-ms, topic | The draft's mode/limit layout was not adopted. `C`/`T` filters are milliseconds. |
| `MAXCODEPAGE=0`, `MAXLANGUAGE=0` | No code-page count. `LANGUAGE` is a 31-byte tag. |
| `EventCategory.parse("CHANNEL")` is null | IRCX event types and operator categories are different planes. |
| ACCESS timeouts are seconds | `ircx_access_store.zig` stores seconds and tests `3600`. The draft says minutes (section 5.1.1). Switching bare numbers to minutes would make every existing entry last 60 times longer. Bare numbers stay seconds. |
| ONJOIN is `PRIVMSG`, ONPART is `NOTICE`, sender is the channel | Section 8.2.12 and 8.2.13. The two characters `\` `n` start another line because section 3 table 1 defines `\n` as the quote for LF, and a raw LF cannot live inside one IRC line. |
| LAG is 0, 1, or 2 seconds for every member | Section 8.2.14. Voice and operators are not exempt. `SLOWMODE` exemptions stay on `SLOWMODE` only. |
| CREATE of a new channel tells the creator `CREATE <channel> <oid>` | Section 6.3. Ordinary `JOIN` does not. |
| Armor TLS cuts | No ECH+HRR, no extra key shares, no AES-CCM, no PQ signing, no DTLS on the TLS listener, no kTLS txrx, no live OCSP fetch, no MESSAGE_V2 activation. |
| Mesh nick rule | Collision renames the loser to the UID. A local clash stays numeric 433. |
| `RESETPASS` does not say whether the account exists. TOTP enroll requires TLS. | Section 10's cleartext warning, applied to the account surface. |

Working-tree work that this map inherits: Armor wildcard name
constraints, LAG, LISTX caller limits, ONJOIN/ONPART wire shape, Help
topics, and the CREATE oid line. None of that is deployed.

## 3. Security findings that constrain every new idea

### 3.1 A 32-bit counter is not a capability

Section 4.2 defines an OID as `0` plus eight hex digits. Section 8.2.1
says it may optionally replace the channel name, and that ordinary users
may not read it when the channel is SECRET or PRIVATE. The value `"0"`
means the shortcut is unsupported.

Onyx Server assigns `World.next_oid` from 1 upward (`src/daemon/world.zig`,
the `next_oid: u32 = 1` field). `PROP OID` formats it as `0` plus eight
lowercase hex digits. `channelBuiltinGet` will return that value to any
caller who already knows the channel name. OID is not in the secret-key
tier, so a non-member who can name a secret channel can also read its
counter.

If `JOIN 00000001` resolved the counter, a client could walk
`00000001`, `00000002`, … and learn every room that has ever existed on
that node, including SECRET, PRIVATE, and HIDDEN. A random `u32` does
not fix it. Four billion names are enumerable on a local network.
Section 8.2.1 already refuses the read to ordinary users on secret and
private rooms. The shortcut has to be at least that strict.

Rule for any later OID work:

- A token is an OID only when it is `0` plus exactly eight hex digits.
  Any other token, including `#0abc12345`, stays a literal name.
- Resolve it only to a channel the caller may already see: public, or a
  secret/private/hidden room where the caller is a member or a network
  operator.
- Unknown and invisible return the same `ERR_NOSUCHCHANNEL`. No
  different numeric, no different text, no timing branch that depends
  on existence beyond the map lookup the server already does for a
  missing name.
- `000000000` (value 0) never resolves. Creation already omits oid 0.
- Do not add a longer random bearer in the same slice. A member-visible
  label is enough. A secret join token is a different feature, and it
  would need expiry, rotation, and revocation.

Until that gate exists, the shortcut stays unimplemented. Advertising
`OID=0` in the `800` option list is the honest draft signal.

### 3.2 EVENT ADD is wider than the published contract

`docs/reference/ircx/m_ircx_event.md` says an ordinary client may
subscribe only to `MEDIA`. `CHANNEL`, `MEMBER`, and `USER` are
operator-only. The code does not match that page:

- `clientIrcxTypeAllowed` lets a non-oper `ADD` `CHANNEL`, `MEMBER`, and
  `MEDIA`. `USER` stays operator-only.
- `EVENT CHANGE` rejects a non-oper unless the type is `MEDIA`.

Delivery of `CHANNEL` / `MEMBER` / `MEDIA` is membership-gated
(`mediaEventAllowed`), so this is not a network-wide presence feed.
It is still two contracts. Members already see `JOIN` and `PART`.
A second subscription plane is useful only if it cannot outlive
membership or see a room the client is not in.

Chosen contract, unless a later review shows a client that already
depends on the wider `ADD`: non-opers may `ADD`, `CHANGE`, and `DELETE`
only `MEDIA`. `CHANNEL` and `MEMBER` follow the published page and
become operator-only. Do not widen `CHANGE`.

### 3.3 Cleartext is the draft's own bug

Section 10 says a middleman can delete every strong mechanism from the
`800` list and leave a password. Onyx Server's real authentication is
IRCv3 SASL (`PLAIN`, `SCRAM-SHA-256`, `EXTERNAL`, `OAUTHBEARER`) plus
IRCX `AUTH` over the same router. The evolution is not a new package.
It is a refusal:

- On a plaintext listener, do not complete a password `AUTH` or
  `AUTHENTICATE PLAIN`. Challenge-response (`SCRAM`) and channel-bound
  methods (`EXTERNAL` with the TLS certificate, WebAuthn) are the ones
  section 10 asks for. `SCRAM` on plaintext still sends no password,
  but it sends a verifier exchange that should not be the recommended
  path. Prefer failing password mechanisms closed when `conn` has no
  TLS, matching TOTP enroll.
- The `800` mechanism list must be the list the server will actually
  accept on that connection. Do not advertise `PLAIN` on a socket that
  will refuse it.

This slice needs a test that a plaintext `AUTH PLAIN` fails and a TLS
`AUTH PLAIN` still works. It must not weaken `RESETPASS` or TOTP.

Landed 2026-10-16 as W1-B. A plaintext socket omits PLAIN and SCRAM
from numeric 800, CAP `sasl=`, and SASLINFO, and refuses them.
`AUTH PLAIN I` is numeric 910. `AUTHENTICATE PLAIN` is numeric 904.
TLS still completes PLAIN. Native test
`threaded server: plaintext password SASL is refused` passed
(74 passed, 0 failed; binary `9031ecc91eb7ec911b6ea6205eab8cd3`).

### 3.4 Wildcards and reflected text

`ACCESS` masks accept `*` and `?` (section 5.1.1). A `DENY *` on
`ACCESS *` is a network lock. That command is already operator-only
through `SACCESS`. Keep it that way. A channel `DENY` must not be
creatable by a member who is not a host.

`ONJOIN` / `ONPART` / `ACCESS` reasons / topics are attacker-controlled
and reflected. The live rule stays: a stored CR, LF, NUL, or other C0
drops the value or the line. The quoted `\n` is the only multiline
form. Do not grow a second encoder.

### 3.5 Unicode is a spoofing project, not a prefix project

Section 3 defines a quote table (`\b` space, `\c` comma, `\\`, `\r`,
`\n`, `\t`) and the `%#`, `'`, and `^` prefixes so old clients can see
a hex nick. Implementing those prefixes without a confusable-character
policy creates homoglyph nicks and bidi overrides. The secure order is:
reject bidi overrides and mixed-script confusables in the nick and
channel validators that already exist, and only then consider `%#` and
`'` names. The `^` hex form is a display alias. It must not be a second
account.

## 4. Feature map

Each row is one slice. "Invented" means it is not required by the 1998
text. It still has to fit the mesh, the session model, and section 10.

### 4.1 IRCX

| ID | Feature | Security rule | Owner | State |
| --- | --- | --- | --- | --- |
| E-1 | Visibility-safe OID shortcut, section 3.1 | Same error for missing and hidden. No counter walking. | `server.zig` plus `world.zig` lookup. One integrator. | In progress 2026-10-16. JOIN only. `OID=visible` in the same change. |
| E-2 | `800` option list tells the truth: `OID=0` until E-1 ships, then `OID=visible`. Mechanisms match what that socket will accept. | No advertised method the socket refuses, and no method the socket accepts that is missing from the list. | `server.zig` ISIRCX reply | After E-1, or `OID=0` immediately if the list currently implies a shortcut |
| E-3 | Narrow non-oper `EVENT ADD`/`DELETE` to `MEDIA` | Matches `m_ircx_event.md`. Membership gate stays. | `server.zig` | After a test shows no shipped client sends `EVENT ADD CHANNEL` |
| E-4 | `ACCESS` bare numbers stay seconds. Help and the command page say so. Optional suffix `s`/`m`/`h` may be added later; bare stays seconds. | Do not reinterpret stored entries. | `help_db.zig` if the line is wrong; no store change | Help line says seconds. `HELP topics cover IRCX and services` passed 2026-10-16, including the seconds assertion and the SUCCESSOR "10 minutes" line. |
| E-5 | Whisper versus auditorium | A `+x` member who cannot see another member must not learn that member's presence by whispering them. Same error as a nick that is not in the channel. | `server.zig` `handleWhisper` | Landed as W1-A. Local hidden member is 441 with no delivery. Remote hidden nick is 401, matching a nick the roster does not list. `+w` stays a total 923 denial. Native `whisper auditorium returns 441` passed 2026-10-16 (74 passed, 0 failed in that filtered run). |
| E-6 | `DATA` origin classes | Client tags cannot be `SYS`, `ADM`, `OWN`, or `HST` without privilege. A server-originated `DATA` line carries a prefix the client cannot forge. | `server.zig` `handleData` and `deliverServerOriginData` | Landed 2026-10-17 as W2-B. Client `DATA`, `REQUEST`, and `REPLY` stay `nick!user@host`. An operator reserved tag stays on that nick. Server-authored DATA uses the bare server name and is not relayed as a client. Native `server DATA origin is the server name and client DATA keeps its nick` passed (74 passed, 0 failed). Full `zig build test` has not been run. |
| E-7 | Quoted Unicode names | Only after the confusable and bidi rejector is in the existing nick and channel validators. | validator module, then IRCX prefixes | Later |
| Privacy modes | User `+D` `+G` `+Z` `+I` `+V` `+W` `+T` and channel `+c` NOCOLOR, `+B` NOBOT, `+K` FOUNDERKICK | `+D` and `+T` filter channel chatter only. `+Z` is stricter than ACCEPT and fails closed on a relay frame that has no TLS bit. `+c` rejects formatting, including hex colour 0x04. `+B` does not apply to the founder of a new channel. `+K` runs after the rank check. No operator exception on channel `+w`. | `usermode.zig`, `chanmode_ext.zig`, `server.zig` | Landed 2026-10-16. Native `privacy modes gate direct messages joins kicks whois and invites` passed. Filtered `test.real` `1f3166b30d48c0aeaa89fdcddb81d392`: 79 passed, 0 failed. ISUPPORT `CALLERID=g` and `DEAF=D`. Cap `onyx/privacy` value `umode=DGIZTVW,cmode=cBK`. CHANMODES `beIZ,k,lfj,imntsCTNgSMWOAphuadErzxwVUFDcBK`. Extended bits 20–22. Checkpoint version stays 2. Full `zig build test` has not been run. |

### 4.2 Services

Services are the account, channel, memo, and oper commands. No new
pseudo-client.

| ID | Feature | What the person gets | Security rule |
| --- | --- | --- | --- |
| S-6 | Account self-audit | `ACCOUNTINFO LOGINS` lists up to 8 sign-ins: time, mechanism, TLS, and an 8-byte prefix. The caller reads their own rows. An operator may name another account. `LOGINS` is the subcommand. | Landed 2026-10-16. Password checks do not write a row. IDENTIFY, recovery LOGIN, passkey AUTH-FINISH, SASL success, and IRCX AUTH do. No full fingerprint is stored. Plaintext IRC test saw `mechanism=password`, `tls=clear`, `prefix=-`, and numeric 481 for another account. The W1-C test saw `tls=tls` and two 8-character certificate prefixes, and not the fingerprint tails. |
| S-7 | New-device notice | A new certificate prefix, or a new passkey prefix, tells the account's other live sessions. The current connection is skipped. | Landed as W1-C on 2026-10-16. Notice text is `New sign-in on your account ({mechanism}).` Delivery uses `deliverNoticeTo` and a failed send does not fail the login. Native `new sign-in notice reaches the other session with a certificate prefix` passed (74 passed, 0 failed): a new certificate prefix notices the other session only, a repeated prefix does not, and a full send queue still logs the new session in. The passkey case stays on the `loginPrefixIsNew` unit test. The ring of 8 is the only memory, so a prefix that rotates out can look new again. |
| S-8 | Founder-transfer hold | `SUCCESSOR SET` waits 10 minutes before it replaces the armed successor. CLEAR during the wait cancels the change. SHOW and a drop during the wait still use the armed name. | Hold is `successor_hold_ms` (10 minutes). Store test and the threaded SUCCESSOR test passed on 2026-10-16 after the test clock advanced by the hold. The SET notice still names the pending account immediately. |
| S-9 | Passkey-only lock | `WEBAUTHN LOCK` refuses password, PLAIN, and SCRAM after a passkey is stored. | Default off. `ACCOUNTSET` cannot set the bit. LOCK without a stored passkey returns `PASSKEY_REQUIRED`. IRC test: bind a passkey, LOCK, `passkey_only=true`, and a later password IDENTIFY fails. A recovery-code password replacement clears the bit. Recovery LOGIN itself stays available. |
| S-10 | Expiring bot grants | `BOTGRANT` without an expiry is rejected. The grant names one channel and one command. | A grant is not a network oper. Override and `SACCESS` stay separate. |
| S-4 | Reply audit | Compare `handleRegister`, `handleIdentify`, `handleChannel`, and `handleMemo` to the command pages. Patch only a line that contradicts the page. | Do not weaken S-2. |

### 4.3 Mesh

Undertow has no confirmed 64-peer ceiling (the scale audit returned no
patch). Do not invent one. The mesh work that is worth doing is
visibility and integrity.

| ID | Feature | Security rule |
| --- | --- | --- |
| M-5 | Secret-channel fanout audit | Audited 2026-10-16, no patch while E-1 owns `server.zig`. WHO (`handleWhox`) and targeted NAMES hide secret, private, and hidden rosters from non-members. Bare NAMES also skips private rooms the caller is not in. LIST and LISTX skip secret and hidden only, so a private room's name, count, and topic are enumerated, including a room materialized from a remote MODE burst on a node with no local member. Remote secret LISTX is filtered once `channel_secret_flag_bit` arrives. The LIST comment records a window where a new remote secret or hidden name can show between the membership burst and the mode burst. LISTX rows do not carry OID. |
| M-6 | Property witness | Channel properties are already signed on the mesh. An operator `STATS` or `MESH` line may show the origin node and the HLC. Do not hand the signing key, the raw signature, or a forgeable "trusted" bit to ordinary clients. |
| M-7 | Netsplit rejoin | A kick, a ban, or an `ACCESS DENY` that happened during a partition still applies when the peer returns. The rejoining client does not get the room back because their nick used to be there. |
| M-8 | No new wire version | Do not flip MESSAGE_V2, FEC, or kTLS txrx under this map. |

### 4.4 Other server surfaces

| ID | Feature | Why it is in this map |
| --- | --- | --- |
| X-1 | Plaintext password refusal | Landed as W1-B on 2026-10-16. Plaintext sockets omit and refuse PLAIN and SCRAM. TLS still completes PLAIN. Native `plaintext password SASL is refused` passed (74 passed, 0 failed). |
| X-2 | Bidi and confusable rejector | Landed 2026-10-16 with the knock oracle. Existing nick and channel validators reject bidi, invisibles, fullwidth lookalikes, and mixed letter scripts. One script stays valid. No new prefix. `%#` stays. Native `knock on a hidden channel matches a missing channel` passed (77 passed, 0 failed). E-7 does not start in that change. |
| X-3 | Help stays one store | `help_db.zig` is the long form. `COMMANDS` is the index. New slices add a topic in the same change as the command. |
| X-4 | CLI `verify` name constraints | `src/cli/verify_cmd.zig` still does not apply the Armor name-constraint check the handshake now applies. Fix the checker or stop the comment from claiming it does. No new TLS feature. |
| X-5 | Client tree | `/home/kain/onyx` renders these bytes. It is out of scope until a daemon slice has a stable line. |

## 5. Order

The first three are security closures. Features that add surface area
come after them.

1. E-1 visibility-safe OID, with the tests in section 6. One integrator.
   No second writer on `server.zig`.
2. E-3 EVENT contract, same integrator, next turn, after E-1's tests are
   green. Include a regression that a non-oper `EVENT ADD CHANNEL`
   receives the same privilege error as `EVENT ADD USER`.
3. X-1 plaintext `AUTH PLAIN` / `AUTHENTICATE PLAIN` refusal, with a TLS
   positive test. Landed as W1-B on 2026-10-16.
4. E-5 whisper versus auditorium. Fix only if a non-visible member can
   be distinguished from a missing nick.
5. M-5 secret-channel fanout audit. Read-only first. A patch only if a
   frame carries a hidden name to a peer with no member.
6. S-6 self-audit and S-7 new-device notice. Landed. The certificate
   IDENTIFY path is native-proven as W1-C on 2026-10-16. The passkey
   prefix stays on the `loginPrefixIsNew` unit test.
   Privacy user modes and channel `+c` `+B` `+K` landed the same day.
   Native filtered run: 79 passed, 0 failed. That slice does not start
   W2-D, W2-B, or E-3. W2-D and X-2 landed later the same day: hidden
   `KNOCK`, `TOPIC`, and `MODE` share the missing-channel 403, knocks
   are limited to 3 per 30 seconds (712), and the spoof rejector is in
   the existing validators. Invite-exception expiry is not landed.
   Native filtered run: 77 passed, 0 failed. E-7 and E-3 stay unstarted.
7. S-8, S-9, S-10. One each. S-9 defaults off.
8. E-6 DATA origin classes. Landed 2026-10-17 as W2-B. Native filtered run: 74 passed, 0 failed. E-3 and E-7 stay unstarted.
9. X-2 confusable rejector. Landed 2026-10-16 with W2-D. E-7 stays a
   separate decision and does not start in that change.
10. X-4 CLI verify comment and checker.
11. Full `zig build test`, then ReleaseSafe on the mesh or auth slice
    that shipped. Deploy only when that evidence exists and the operator
    asks.

Do not run 1 and 2 as two agents. Both edit `server.zig`.

## 6. Tests each slice must have

E-1, on a heap `createTestServer`, native `test.real`:

- Create `#public`. `JOIN` of its oid from a second client lands in
  `#public`.
- Create a secret channel. A non-member `JOIN` of its oid returns
  `ERR_NOSUCHCHANNEL` and does not reveal the name. A member `JOIN` of
  the oid still works.
- `JOIN 000000000` and `JOIN 0deadbeef` (no such room) return the same
  numeric and the same trailing text as each other.
- `JOIN #plain` and `JOIN 0abc` (too short) are unchanged.
- A plain `JOIN` that creates a room still does not emit `CREATE`.
- LAG, LISTX, ONJOIN, and the creator's `CREATE` oid line still pass
  their existing tests.

E-3: non-oper `ADD`/`CHANGE`/`DELETE` of `CHANNEL` and `MEMBER` get the
privilege error. `MEDIA` still adds. An oper can still add `CHANNEL`.

X-1: landed as W1-B. Plaintext password auth fails closed, including
SCRAM. TLS password auth succeeds. The native test names that rule.

M-5: a two-node test, or a unit test of the publish function, shows a
secret channel name absent from the remote LISTX image.

## 7. Anti-patterns

- Implementing `JOIN <oid>` before the visibility gate, because the
  draft "allows a shortcut".
- Replacing the counter with a random `u32` and calling it unguessable.
- Turning `EVENT ADD` up to `USER` for ordinary clients so the client
  can draw a network roster.
- Parsing `\n` inside `ONJOIN` as a raw line break.
- Changing ACCESS bare numbers from seconds to minutes.
- Adding NickServ, MemoServ, or a `TACCESS` verb.
- Advertising `PLAIN` on a socket that refuses it, or accepting `PLAIN`
  on a socket that does not protect it.
- A Unicode nick prefix without a confusable check.
- A mesh frame that includes a hidden channel "for completeness".
- Editing `docs/audit/evidence/` or the frozen 2026-09 gap audit to
  match this map.
- Deploying any slice in this file without an explicit operator request.
- Reviving the 1997 bracketed reply prefix. `labeled-response` is the
  correlation mechanism.
- Adding mode letter `c` because a CREATE example uses it. Section 8.1
  never defines `c`.
- Adding an NTLM `AUTH` success line (`AUTH <name> * <ident> <oid>`) in
  the same change as the plaintext-password refusal.
- Reordering live `ACCESS` evaluation to match a misread of section
  5.1.4. The draft order is OWNER, HOST, VOICE, GRANT, DENY. A rejected
  claim had inverted that into reverse precedence.

## 8. Sources

- Abraham, *Extensions to the Internet Relay Chat Protocol (IRCX)*,
  draft-pfenning-irc-extensions-04, June 1998, sections 2, 3, 4.1, 4.2,
  5.1, 5.2, 5.3, 6.3, 8.2.1, 8.2.12–8.2.14, and 10.
  <https://www.ietf.org/archive/id/draft-pfenning-irc-extensions-04.txt>
- IRCX, Wikipedia, retrieved 2026-10-15.
  <https://en.wikipedia.org/wiki/IRCX>
- Onyx Server live notes: `docs/reference/ircx/README.md`,
  `docs/reference/ircx/m_ircx_event.md`,
  `docs/reference/ircx/m_ircx_access.md`,
  `src/daemon/world.zig` (`next_oid`),
  `src/daemon/server.zig` (`clientIrcxTypeAllowed`, `channelBuiltinGet`,
  `emitCreateOidReply`).
- IRCv3 SASL 3.1 and 3.2, labeled responses, and the chathistory draft,
  <https://ircv3.net/irc/>. None of those specifications cite IRCX.
- Draft 00 (31 January 1997) for the dropped bracketed reply prefix,
  <https://www.ietf.org/archive/id/draft-pfenning-irc-extensions-00.txt>.

## 9. Cross-check, 2026-10-15

An independent pass re-read the draft and the IRCv3 specifications.
Status of that pass: partial. The gaps are listed below. Nothing in
this section weakens E-1, E-3, or X-1.

Facts added here, because the earlier sections did not state them:

- Section 10 does not mention eight-hex channel shortcuts, `ACCESS`
  wildcards, or embedded ONJOIN newlines. Those are protocol
  definitions. The enumeration rule in section 3.1 is an Onyx rule
  written because `next_oid` is a counter and a global shortcut would
  be an existence oracle. The draft's silence is why the rule is
  written here. The draft says "eight hexadecimal characters," not
  "32-bit." Sixteen to the eighth is the size of that space.
- `AUTH` syntax is `AUTH <name> <seq> [:<parameter>]`. `<seq>` is `I`,
  then `S`, or `*` to abort. The draft's success example is
  `AUTH <name> * <ident> <oid>`. The mechanism reference is
  `draft-myers-auth-sasl-07`, a work in progress in 1998, not a
  finished SASL RFC. Onyx Server keeps the IRCv3 `AUTHENTICATE` router
  for the same pre-registration need. X-1 changes which mechanisms a
  plaintext socket will complete. It does not add a second success
  line.
- The OID returned by `CREATE` and by `CLONE` is implementation
  dependent, and the draft requires the value `0` when the shortcut is
  unsupported. That is the same signal as E-2's `OID=0`.
- The redirect reason, the `ACCOUNT` property text, `SERVICEPATH`, the
  IRCX option list, and the unknown-error numeric are implementation
  dependent. A later slice must not treat a missing sentence in the
  draft as a wire bug.
- Section 5.5 subscribes a sysop or a sysop manager to named events.
  The examples include CHANNEL, MEMBER, SERVER, CONNECTION, SOCKET,
  and USER. The full type list and the mask rules are unspecified, and
  another implementation may choose which of those a sysop sees.
  Ordinary-client `MEDIA` is an Onyx plane. E-3 keeps that plane and
  returns CHANNEL and MEMBER to the operator scope the draft describes.
- Section 5.1.4 processes `ACCESS` entries as OWNER, HOST, VOICE,
  GRANT, DENY. This note records that order. It does not retune the
  live store.
- Channel mode `+w` is unreconciled inside the draft. Section 5.13.3
  still allows a whisper from or to a channel operator. Section 8.1.11
  says NOWHISPER prevents messages addressed to specific nicknames in
  the channel. `src/proto/whisper.zig` denies the command when `+w` is
  set, before recipient selection, numeric 923. That is the live rule.
  This map does not add an operator exception. E-5 is the separate
  auditorium (`+x`) question: a member the caller cannot see must look
  like a nick that is not in the channel.
- The letter `z` is user-mode GAG and channel-mode SERVICE. They stay
  on different planes. Owner mode `+q` uses the prefix `.`.
- `ONPART` is its own property. The draft says it may be set and read
  like `ONJOIN`. It does not say the two strings are the same text.
  The live wire shape in section 2 stays.

Coverage the pass left open:

- Wikipedia's IRCX summary does not name ONJOIN, ONPART, or OID, and it
  describes `CREATE` only as a command that creates a channel. The
  draft text wins over that summary.
- The pass did not establish what later vendor IRCX servers added
  beyond draft 04.
- RFC 1459 section 4.2.3.1 leaves its per-command limit sentence
  unfinished ("any combination of 'o' and"). That is an RFC defect.
  It is not an Onyx change.
