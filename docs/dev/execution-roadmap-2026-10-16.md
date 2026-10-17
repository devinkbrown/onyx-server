# Onyx Server execution roadmap (2026-10-16)

This is the execution map. The 2026-10-15 IRCX note
(`docs/dev/ircx-evolution-roadmap-2026-10-15.md`) stays the research
record. Where that note's order and this file disagree, follow this
file. Do not deploy, push, or signal a live node from this map.

Source of truth is the tree on `portability/openbsd` at `c5d14934`,
plus the uncommitted work listed below. `docs/audit/evidence/` is a
frozen copy and is not compiled. `docs/ROADMAP-GAPS-2026-09.md` is
historical. GAP-P0a (005 / CHANMODES / CHATHISTORY) is already
advertised. Do not re-implement it.

## 1. Already in the tree

These are coded. Do not revert them, and do not mark a later slice
done by editing their tests away.

| Slice | What the tree does | Evidence limit |
| --- | --- | --- |
| Armor name constraints | A single-label wildcard SAN is the set of one-label expansions. An excluded subtree matches if any expansion is inside. A permitted subtree matches only if every expansion is inside. The accepted name is also checked against every presented CA and the matching trust anchor. | Armor suite 121 passed, 3 skipped, on the musl qemu run. `src/cli/verify_cmd.zig` does not call that checker yet (X-4). |
| IRCX LAG | `PROP LAG` is 0, 1, or 2 seconds for every member. Voice and operators are not exempt. `SLOWMODE` exemptions stay on `SLOWMODE`. | Landed with the October IRCX slice. |
| LISTX limit | The second parameter is accepted and clamped. Numeric 816. Layout stays `<channel> <members> <created_ms> <topic_ms> :<topic>`. | Do not "fix" that layout back to the 1998 mode/limit row. |
| ONJOIN / ONPART | ONJOIN is `PRIVMSG` to the joiner only. ONPART is `NOTICE` to the parter only. The channel name is the sender. The two characters `\` `n` start another line. A real CR, LF, or NUL is rejected. | Max 255. |
| CREATE oid | After a successful create, only the creating client receives `:{server} CREATE {channel} {oid}`. Ordinary JOIN does not. A failed CREATE does not. Clone CREATE does. | oid `0` is omitted. |
| Help | `help_db.zig` covers IRCX and account commands. ACCESS bare timeout is seconds. SUCCESSOR names the 10-minute hold. | `HELP topics cover IRCX and services` passed 2026-10-16. |
| E-1 JOIN oid | A token is an OID only when it is `0` plus eight hex digits. Resolve only a channel the caller may already see. Unknown and invisible both return 403 `No such channel` and echo the caller's token. `000000000` never resolves. `JOIN 0` stays part-all. The 800 list says `OID=visible`. | The dedicated native test log has not been read by the parent session. Do not revert the gate. |
| S-6 LOGINS | `ACCOUNTINFO LOGINS` lists up to 8 rows: time, mechanism, TLS, 8-byte prefix. Self, or an operator naming another account. `LOGINS` is the subcommand. Another account without oper is 481 before lookup. | Native threaded test passed 2026-10-16. No full fingerprint is stored. The plaintext test used `prefix=-`. The W1-C in-process test saw `tls=tls` and the first 8 characters of two certificate fingerprints, and not the tails past byte 8. |
| S-7 new-device notice | Text is `New sign-in on your account ({mechanism}).` via `deliverNoticeTo`. A failed send does not fail the login. | Native W1-C test passed 2026-10-16. A second IDENTIFY with a new certificate prefix notices the first session only. A repeated prefix does not. `sendq_cap = 0` still logs the new session in. The ring of 8 is the only memory. The passkey prefix path stays on the `loginPrefixIsNew` unit test. |
| S-8 successor hold | `SUCCESSOR SET` of a different account waits `successor_hold_ms` (10 minutes). SHOW and a drop during the wait use the armed name. | Store test and the threaded SUCCESSOR test passed after the test clock advanced by the hold. The SET notice still names the pending account immediately. |
| S-9 passkey lock | `WEBAUTHN LOCK` sets passkey-only after a stored passkey. Password, PLAIN, and SCRAM then fail. Recovery-code password replacement clears the bit. | Native test: bind, LOCK, `passkey_only=true`, later password IDENTIFY fails. `ACCOUNTSET` cannot set the bit. |
| S-10 bot grants | `BOTGRANT` is already oper plus `server_admin`, with expiry. | No code change in the services slice. |
| Services proof | Native `test.real` `92854571b49d3fb109a3b2fc7c0f3ca9`: 78 passed, 0 failed, 0 leaked. | That binary does not include the whisper gate below. Qemu `createTestServer` fails in `SO.INCOMING_CPU` with `error.Unexpected`. That is the runner, not the assertion. Full `zig build test` has not been run. |
| Privacy modes | User `+D` `+G` `+Z` `+I` `+V` `+W` `+T` and channel `+c` `+B` `+K`. `+D` and `+T` filter channel chatter only. `+Z` is checked before `+G`. ACCEPT does not bypass `+Z`. Remote `+Z` fails closed. `+c` rejects formatting, including 0x04. `+B` blocks a bot joining an existing channel. `+K` limits kicks to the founder after the rank check. ISUPPORT adds `CALLERID=g` and `DEAF=D`. Cap `onyx/privacy` is `umode=DGIZTVW,cmode=cBK`. CHANMODES is `beIZ,k,lfj,imntsCTNgSMWOAphuadErzxwVUFDcBK`. Extended bits 20–22. Checkpoint version stays 2. | Native `test.real` `1f3166b30d48c0aeaa89fdcddb81d392`, log `/tmp/zig-modes-native.log`: 79 passed, 0 failed, exit 0 on 2026-10-16. The privacy gate test OK in 78ms. Qemu of the same binary dies in `SO.INCOMING_CPU`. Full `zig build test` and ReleaseSafe have not been run. |

Native server tests call `createTestServer` (heap `initInPlace`).
`Server.init` by value materializes the daemon on the caller's stack
and faults. Build with `/tmp/zig-ivy/bin/zig` through
`python3 /tmp/zig-ptrace.py`, caches under `/tmp/zig-cache*`,
`-Dtarget=x86_64-linux-musl -Dcpu=x86_64`. As of 2026-10-17
`/tmp/zig-ptrace.py` runs project binaries on this kernel and
qemu-wraps only the compiler host tools `maker` and `configurer`.
Do not export `LD_LIBRARY_PATH`.

## 2. Closed cuts

Do not reopen these. They are decisions, not unfinished work.

- ECH combined with HelloRetryRequest stays fail-closed (`EchHrrUnsupported`, `HelloRetryRequestUnsupported`).
- ChaCha-only HPKE for ECH. No extra key shares beyond X25519, P-256, and X25519MLKEM768. No AES-CCM. No zlib-only certificate compression.
- No `armor enc`, no `s_server`, no `s_client -connect`.
- Caller-supplied CRL and CT stay default-off (`ct_logs`, `require_sct`, `require_crl`). `enforce_cert_signature_algorithms` stays default-off.
- BoGo stays on the pinned 24/3 lane. No delegated-credential mint. No CLI sandbox.
- PQ signing stays out. Verify-only ML-DSA and SLH-DSA is the 1.x posture.
- No DTLS on the TLS listener. No kTLS txrx. No live OCSP fetch. No `defer_taskrun`. No MESSAGE_V2 activation.
- No NickServ-style pseudo-client. No second AKICK store. No `TACCESS`, `BTPROP`, `OPFORCE`, or `SVSJOIN`.
- No Comic Chat `DATA` avatar. `WALLOPS` stays `EVENT BROADCAST`.
- MODEX numerics stay 826/827. The command page that still says 806/807 is stale. Do not change the live numeric.
- `MAXCODEPAGE=0` and `MAXLANGUAGE=0`. `EventCategory.parse("CHANNEL")` stays null while the IRCX event type parses that token.
- ACCESS bare numbers stay seconds. The draft's minutes would multiply every stored entry by 60.
- `RESETPASS` replies stay identical whether or not the account exists. TOTP enroll stays TLS-only.
- `NOTICE` never emits an error reply. `CLIENT` is not a join filter. ONJOIN is not a join version filter.
- `+w` NOWHISPER is numeric 923 for everyone, before recipient selection. No operator exception.
- Mesh nick collision renames the loser to the UID. A local clash stays 433. Do not invent a 65-peer ceiling. The scale audit found none.
- Do not edit `build.zig` as a product change. Do not edit the frozen evidence copy of `services.zig`.

## 3. Wave 1 — close the privacy holes

One writer owns `src/daemon/server.zig` for the whole wave. Do not
spawn a second integrator.

### W1-A. Auditorium whisper (landed, native test green)

`+x` already hides a regular member from another regular in NAMES,
WHO, and JOIN/PART. `handleWhisper` delivered whenever `isMember` was
true and never called `auditorium.visibleTo`. A regular could prove
another regular was in the room by whispering them.

Contract:

- Local member the sender cannot see: numeric 441 `They aren't on that channel`. No delivery, no mesh admit, no relay.
- Remote nick the sender cannot see: numeric 401 `No such nick`, the same reply as a nick the roster does not list. 441 on that path would admit the nick is in the room.
- The sender's own nick is not hidden from the sender.
- An operator is visible to everyone. An operator or a voiced member can whisper a regular.
- `+w` stays 923 for everyone, including operators.
- An unknown rank is treated as regular. Two roster rows for one nick use the less visible rank.
- Inbound legacy whisper and MESSAGE_V2 channel-whisper use the same predicate before delivery. The signed mode bits on a relay are not a visibility proof.

Test: `threaded server: whisper auditorium returns 441`, on a heap
`createTestServer`, native `test.real`. Off-channel 441, hidden-member
441 with no delivery, operator and voice still deliver, `+w` still 923.

Native run 2026-10-16, binary
`/tmp/zig-cache-svc-local/o/bf5105be455a2c9a15e209f44c32ed1d/test.real`:
that test OK in 139ms. Summary 74 passed, 0 skipped, 0 failed, 0
leaked, elapsed 139ms, exit 0. The qemu wrapper of the same binary
fails in `SO.INCOMING_CPU` with `error.Unexpected` before the
assertion. That runner failure is not the contract. Full `zig build
test` and ReleaseSafe have not been run for this slice.

### W1-B. Plaintext password refusal (landed, native test green)

On a connection with no TLS, do not complete password `AUTH` or
`AUTHENTICATE PLAIN`. A TLS listener still accepts PLAIN. The 800
mechanism list, CAP `sasl=`, numeric 908, and `SASLINFO` on that
socket are the list the socket will complete. PLAIN and SCRAM are
omitted when the socket will refuse them.

SCRAM on plaintext sends no password, but it sends a verifier
exchange. Password mechanisms fail closed when the session flag is
false, matching TOTP enroll. The flag is true when the connection is
TLS or when a test config sets `allow_plaintext_password_sasl`. That
latch defaults false and has no TOML key. Helix adopt sets the flag
when it restores `is_tls`. `RESETPASS` and TOTP enrollment are
unchanged. EXTERNAL, OAUTHBEARER, SESSION-TOKEN, and ANONYMOUS stay
available. IDENTIFY stays a post-registration password command.

IRCX `AUTH` is `AUTH <package> <I|C|*>`. The refusal test sends
`AUTH PLAIN I`. A bare `AUTH PLAIN` is numeric 461 before the
password gate.

Test: `threaded server: plaintext password SASL is refused`, on heap
`createTestServer` instances, native `test.real`. TLS in-process CAP
LS contains `PLAIN` and `AUTHENTICATE PLAIN` for admin/onyx sets the
account. The plaintext socket's CAP LS and numeric 800 omit `PLAIN`,
800 still carries `OID=visible`, `AUTHENTICATE PLAIN` is 904 with no
903, and `AUTH PLAIN I` after registration is 910.

Native run 2026-10-16, binary
`/tmp/zig-cache-svc-local/o/9031ecc91eb7ec911b6ea6205eab8cd3/test.real`,
log `/tmp/zig-plain-native.log`: that test OK in 104ms. Summary 74
passed, 0 skipped, 0 failed, 0 leaked, elapsed 104ms, exit 0. The
qemu wrapper of the same binary fails in `SO.INCOMING_CPU` with
`error.Unexpected` before the assertion. That runner failure is not
the contract. Full `zig build test` and ReleaseSafe have not been run
for this slice.

### W1-C. Login notice and certificate prefix (landed, native test green)

Two TLS sessions on one account. IDENTIFY with a certificate prefix the ring has not seen notices the other session: `New sign-in on your account (password).` The signing-in session does not receive that line. The same prefix a second time does not notice. `ACCOUNTINFO LOGINS` shows `tls=tls` and an 8-character prefix, and does not show the rest of the fingerprint. A recipient with `sendq_cap = 0` still lets the new session become the account.

The fixture assigns `session.tls_certfp` and `is_tls` on in-process clients and calls `handleIdentify`. It does not exercise a passkey prefix or a SASL success hook. Those stay on the earlier unit test and the SASL audit hook.

Test: `new sign-in notice reaches the other session with a certificate prefix`, native `test.real`.

Native run 2026-10-16, binary
`/tmp/zig-cache-svc-local/o/8d76b7be47721260f29f132449b731a6/test.real`,
log `/tmp/zig-notice-native.log`: that test OK in 14.936s. Summary 74
passed, 0 skipped, 0 failed, 0 leaked, elapsed 14.936s, exit 0. The
qemu wrapper of the same binary fails in `SO.INCOMING_CPU` with
`error.Unexpected` before the assertion. That runner failure is not
the contract. Full `zig build test` and ReleaseSafe have not been run
for this slice.

### Privacy modes (landed, native test green)

Client-writable user modes, appended after `override` so earlier ordinals stay stable: `+G` common channel, `+Z` TLS-only direct messages, `+I` hide idle, `+V` no invite, `+W` WHOIS notify, `+T` no channel notice. Existing `+D` now drops channel PRIVMSG, NOTICE, and TAGMSG. Channel `+c` NOCOLOR, `+B` NOBOT, and `+K` FOUNDERKICK are extended flags on bits 20, 21, and 22. `NOTICE` still never emits an error numeric. There is no operator exception on channel `+w`.

`onyx/privacy` advertises `umode=DGIZTVW,cmode=cBK`. ISUPPORT adds `CALLERID=g` and `DEAF=D`. HELP MODE names the same letters. WHOIS 320 covers `+G`, `+Z`, and `+V`.

Test: `privacy modes gate direct messages joins kicks whois and invites`, plus the user-mode ordinal test, the spare-bit test, the WHOIS 320 test, the CHANMODES honesty test, and the world checkpoint round trip. Native `test.real` `/tmp/zig-cache-svc-local/o/1f3166b30d48c0aeaa89fdcddb81d392/test.real`, SHA-256 `470ebdb205e70c2876ae28688f5782b7e41d2418c6b09bf02e372cee329de80b`, log `/tmp/zig-modes-native.log`: 79 passed, 0 skipped, 0 failed, 0 leaked, elapsed 82ms, exit 0. The privacy gate itself OK in 78ms. The qemu wrapper dies in `SO.INCOMING_CPU` with `error.Unexpected` inside `createTestServer`. That runner failure is not the contract. Full `zig build test` and ReleaseSafe have not been run.

### Knock oracle and identifier spoof (landed, native test green)

`KNOCK`, `TOPIC`, and `MODE` on a secret, private, or hidden channel the caller is not in return the same 403 `No such channel` as a missing name. Operators are not exempt. A public `+i` channel still delivers 710 and 711. An open public channel is still 713. A member is still 714. The notify path allows 3 knocks per connection per 30 seconds and then returns 712 `Too many KNOCKs for this channel`. A 403 does not spend that budget. No `MEMBER KNOCK` event is published for a hidden name.

Invite-exception expiry is not in this slice. `ListEntry` stores `set_at` only, the ownership fixture uses `set_at=4`, and a TTL from that field would expire checkpointed `+I` rows without a checkpoint version change. The 346 list already shows `set_at`. No new store.

Nick and channel validators reject bidi overrides, invisible scalars, fullwidth and mathematical lookalikes, and two letter scripts in one name. A single script stays valid. `%#` and `%&` stay accepted. No `'`, `^`, or new prefix was added. A spoofed nick is numeric 432 and the stored nick does not change. The reply shows `*` so the numeric line itself is not reordered.

Test: `knock on a hidden channel matches a missing channel`, plus `identifier spoof rejects bidi overrides and mixed scripts`, `nick validity is bounded and mapping aware`, and `isChannelName accepts #, &, and %#/%& but not bare names or ^`. Native `test.real` `/tmp/zig-cache-knock-local/o/0670d4ef3deb54c9e96dc9c5e69745ef/test.real`, SHA-256 `d8b85f2bc55996bb0c1587fa1d6b6164750c9193d6f0728c98d983cfec6f1a38`, log `/tmp/zig-knock-native.log`: 77 passed, 0 skipped, 0 failed, 0 leaked, elapsed 77ms, exit 0. The knock test itself OK in 77ms. The qemu wrapper dies in `SO.INCOMING_CPU`. Full `zig build test` and ReleaseSafe have not been run.

### DATA origin classes (landed, native test green)

Client `DATA`, `REQUEST`, and `REPLY` stay `nick!user@host`. A line this server authors is `:{server} DATA <target> <tag> :<message>` and the prefix has no `!`. A client-supplied prefix on the inbound line is ignored. `SYS` and `ADM` still require a server operator. `OWN` and `HST` still require channel operator rank or a server operator. An operator's reserved tag stays on that operator's nick prefix. A remote `SYS` or `ADM` tag stays closed. Server-authored DATA is delivered on this node only. It is not copied onto the client relay prefix.

Test: `server DATA origin is the server name and client DATA keeps its nick`. Native `test.real` `/tmp/zig-cache-w2b-local/o/32a8a60c4f687a8016f36da90e01b551/test.real`, SHA-256 `8269f0e39d8030129e508c8f9935811b7d64bd3c53b7eddcbfb1ffbc01740219`, log `/tmp/zig-w2b-native.log`: 74 passed, 0 skipped, 0 failed, 0 leaked, elapsed 75ms, exit 0. The origin test itself OK in 75ms. An earlier qemu wrapper of that binary dies in `SO.INCOMING_CPU`. On 2026-10-17 `zig build test-mod-verbose -Dtest-filter='server DATA origin'` executed the ELF on this kernel (log `/tmp/zig-w2b-runner-fix.log`: 74 passed, 0 failed, exit 0). Full `zig build test` and ReleaseSafe have not been run.

## 4. Wave 2 — IRCX surface that stays fail-closed

### W2-A. EVENT ADD stays wide until the tests move

`m_ircx_event.md` says an ordinary client may subscribe only to
`MEDIA`. The code lets a non-oper `ADD` `CHANNEL`, `MEMBER`, and
`MEDIA`. `USER` is operator-only. `EVENT CHANGE` already rejects a
non-oper unless the type is `MEDIA`. Do not widen CHANGE.

Do not narrow ADD yet. Live tests send `EVENT ADD CHANNEL`. A
non-oper regression that expects a privilege error will fail those
tests, and a shipped client may send the same line. The slice starts
by changing the tests, then the handler, in one change, only after
confirming no deployed client depends on `EVENT ADD CHANNEL`.

### W2-B. DATA origin classes

Landed 2026-10-17. Client `DATA`, `REQUEST`, and `REPLY` keep
`nick!user@host`. A server-authored DATA line uses the bare server
name. Reserved tags stay privilege-gated, and an operator's reserved
tag does not become the server prefix. Remote `SYS` and `ADM` stay
closed. The server line is local. It is not relayed as a client.

### W2-C. Confusable and bidi rejector

Landed 2026-10-16 in the existing nick and channel validators.
`containsIdentifierSpoof` rejects bidi overrides, invisible scalars,
fullwidth and mathematical lookalikes, and two letter scripts. One
script stays valid. No new command. No new `%#`, `'`, or `^` prefix.
Existing `%#` and `%&` stay accepted. The `^` form is still not a
channel name and must never become a second account.

### W2-D. Knock and invite are not presence oracles

Landed 2026-10-16 for the knock, topic, and mode oracles. A secret,
private, or hidden channel the caller cannot see returns the same 403
as a missing name. The notify path is three knocks per connection per
30 seconds, then 712. Probing a hidden name does not spend that budget.
No new store.

Invite-exception expiry is not landed. The `+I` list has `set_at` and
no expiry field. Adding a TTL would change checkpointed rows without a
version bump. The inviter already reads `set_at` on numeric 346.

## 5. Wave 3 — account surface

No pseudo-client. Privileged flags stay the first three bits
(suspended, forbidden, noexpire). `passkey_only` stays out of
`ACCOUNTSET`.

### W3-A. Own session list

`ACCOUNTINFO SESSIONS` lists the caller's live attachments: nick, TLS
or clear, and the node id. No IP, no certificate, no token. An
operator may name another account and gets the same fields. A
non-operator naming another account is 481 before lookup, same as
LOGINS. `SESSIONS` is a subcommand, not an account name.

### W3-B. Oper step-up

A passkey-only account cannot become a network operator on a session
that authenticated with a password or a recovery code. Oper elevation
requires a passkey or EXTERNAL on that session. Recovery stays the
break-glass path back to a password, and that password session is not
an oper session until the account holder signs in with a passkey again.

### W3-C. Reply audit

Compare `handleRegister`, `handleIdentify`, `handleChannel`, and
`handleMemo` to the command pages. Patch only a line that contradicts
the page. Do not change the RESETPASS existence rule.

### W3-D. Memo and grant expiry the holder can see

`MEMO LIST` already stores memos. Show the holder how many are unread
and drop expired rows before the list, with a fixed cap. `BOTGRANT`
without an expiry stays rejected. `BOTGRANT LIST` for the granting
operator shows the channel, the command, and the expiry. A grant is
not a network oper.

## 6. Wave 4 — mesh integrity

Undertow has no confirmed fixed peer ceiling. Do not add one.

### W4-A. Private LIST stays documented

WHO and targeted NAMES hide secret, private, and hidden rosters from
non-members. LIST and LISTX skip secret and hidden only, so a private
room's name, count, and topic are enumerated. That is the current
contract. A patch that hides private rooms is a separate product
decision, not a drive-by.

There is a window where a new remote secret or hidden name can appear
in LIST between the membership burst and the mode burst. Close that
window if a test can show the name on the far node before the mode
arrives. Do not put an OID in a LISTX row.

### W4-B. Property witness for operators

Channel properties are already signed. An operator `STATS` or `MESH`
line may show the origin node and the HLC of one property. Do not hand
the signing key, the raw signature, or a forgeable "trusted" bit to
ordinary clients.

### W4-C. Partition rejoin honors the denial

A kick, a ban, or an `ACCESS DENY` that landed during a partition
still applies when the peer returns. The rejoining client does not
re-enter because their nick used to be in the room. Test with two
nodes, a dropped link, a denial, and a rejoin that is refused.

### W4-D. No new wire version

Do not flip MESSAGE_V2 on, FEC, or kTLS txrx under this map. The
whisper gate may read a V2 whisper that is already admitted. It must
not enable the feature.

## 7. Wave 5 — checker and ship gate

### W5-A. CLI verify uses the handshake name check

`src/cli/verify_cmd.zig` must apply the same name-constraint helper
the handshake applies, or the comment must stop claiming that it does.
No new TLS feature.

### W5-B. Ship evidence

`zig fmt` on touched files. Focused native `test.real` for each wave.
Then full `zig build test`, and record the pass count. ReleaseSafe on
the auth or mesh slice that the wave touched. A fresh reviewer tries
to refute the wave before anyone treats it as releasable.

Deploy only after that evidence and an explicit operator request.
GitHub push is last, after a green mesh acceptance that this map does
not start.

## 8. Order

1. W1-A auditorium whisper. Native test passed 2026-10-16.
2. W1-B plaintext password refusal. Native test passed 2026-10-16.
3. W1-C live new-device notice and TLS certificate prefix. Native test passed 2026-10-16. Privacy user modes and channel modes `+c` `+B` `+K` also passed natively the same day (79 passed, 0 failed).
4. W2-D knock, topic, and mode oracle, plus the W2-C confusable rejector. Native test passed 2026-10-16 (77 passed, 0 failed). Invite-exception expiry stays unlanded.
5. W2-B DATA origin classes. Native test passed 2026-10-17 (74 passed, 0 failed).
6. W2-A EVENT narrowing only after its tests and any known client are moved.
7. W3-A sessions list, W3-B oper step-up, W3-C reply audit, W3-D expiry display.
8. W4-B property witness, W4-C partition denial. W4-A only with a failing test.
9. W5-A CLI verify, then W5-B full test and ReleaseSafe.

W1-A, W1-B, and W2-A all edit `server.zig`. They run one after another.

## 9. Anti-patterns

- Reopening a closed cut in section 2 because a draft or a 2026-09 gap file names it.
- Resolving `JOIN 0abc` or `000000000` as a channel.
- Narrowing `EVENT ADD` while a test still sends `EVENT ADD CHANNEL`.
- Adding an operator exception to `+w`.
- Returning 441 for a remote nick the roster merely hides. That admits membership.
- Trusting relay-signed mode bits as auditorium rank.
- Advertising PLAIN on a socket that will refuse it.
- Storing a full certificate fingerprint in the login ring.
- Calling `Server.init` by value from a test.
- Filtering tests with the single token `LISTX`.
- Editing `docs/audit/evidence/` or `build.zig` to make a slice look done.
- Deploying, pushing, or signaling `onyx-server.service`.
