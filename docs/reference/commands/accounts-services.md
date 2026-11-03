# Accounts and services commands

*Account, service, and persona commands exposed as real server commands — Onyx Server has no pseudo-clients.*

The `accounts` module registers the account and service commands (`src/daemon/modules/accounts.zig`), with additional commands from feature and service modules. Onyx Server services are real server commands that reply through raw server lines and server notices; these handlers do not model pseudo-clients (`src/daemon/server.zig`).

## REGISTER

- Syntax: `REGISTER <account|*> <email|*> <password>`
- Description: Registers an account immediately and logs the session in. `*` uses the current nick as the account name. When mail is configured and an email is supplied, the verification code is sent out of band and the client gets a notice telling it to run `VERIFY <code>`; the code is not shown in-band. Registration applies SASL-account oper elevation when configured, tracks the session, delivers pending memos, applies autojoin, and emits welcome and client-registration side effects.
- Privileges: Registered client.
- Parameters: Account, email or `*`, password.
- Replies: Raw `REGISTER SUCCESS <account> :Account registered`, optional email-status notice, welcome/account side effects.
- Errors: IRCv3 `FAIL REGISTER` with `TEMPORARILY_UNAVAILABLE`, `NEED_MORE_PARAMS`, `ACCOUNT_EXISTS`, `BAD_ACCOUNT_NAME`, `INVALID_PASSWORD`, `INVALID_EMAIL`, `ACCOUNT_FORBIDDEN`.
- Example: `REGISTER alice alice@example.net correct-horse`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig`

## VERIFY

- Syntax: `VERIFY [account] <code>`
- Description: Confirms a pending account email verification token.
- Privileges: Registered client.
- Parameters: Verification code, with an optional account name. The one-argument form verifies the caller's logged-in account.
- Replies: Server notice `VERIFY: your account email is now verified`, `VERIFY: nothing to verify for your account`, or IRCv3 `FAIL VERIFY`.
- Errors: `FAIL VERIFY ACCOUNT_REQUIRED`, `EXPIRED`, `INVALID_CODE`, `TOO_MANY_ATTEMPTS`; missing parameters produce a usage notice.
- Example: `VERIFY alice abcdef012345`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig`

## IDENTIFY

- Syntax: `IDENTIFY <account> <password> [<2fa-code>]`
- Description: Authenticates to an existing account and logs the session in. Performs derived oper elevation, tracks the session, delivers pending memos, applies autojoin, and emits login side effects. When the account has TOTP two-factor auth active (see `TOTP`), a valid 6-digit code is required as the third parameter; a correct password with a missing or wrong code is a failed login (and counts against the brute-force throttle).
- Privileges: Registered client.
- Parameters: Account, password, and — for 2FA accounts — the current TOTP code.
- Replies: Server `NOTICE` confirming login plus account-notify/welcome side effects.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_PASSWDMISMATCH 464`, IRCv3 `FAIL IDENTIFY TEMPORARILY_UNAVAILABLE`, `FAIL IDENTIFY TOTP_REQUIRED` (2FA code missing/incorrect).
- Example: `IDENTIFY alice correct-horse 492817`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig`, `src/daemon/services.zig`

## TOTP

- Syntax: `TOTP <ENROLL | CONFIRM <code> | DISABLE | STATUS>`
- Description: Manages the logged-in account's TOTP (RFC 6238) two-factor authentication. `ENROLL` mints a 160-bit shared secret and returns it plus an `otpauth://` URI for an authenticator app (requires a TLS link — the secret must not cross plaintext). `CONFIRM <code>` activates the enrollment after verifying a code and durably saves the secret. `DISABLE` removes it. `STATUS` reports active/pending/disabled. Enabling or disabling 2FA revokes any existing SASL session token. Once active, every login path enforces the second factor: `IDENTIFY` requires the code; knowledge-factor SASL (PLAIN/SCRAM, over both IRCv3 `AUTHENTICATE` and IRCX `AUTH`) is refused with a pointer to use `IDENTIFY`. EXTERNAL, OAUTHBEARER, and SESSION-TOKEN are not gated by TOTP.
- Privileges: Registered client logged in to an account.
- Parameters: A subcommand; `CONFIRM` additionally takes the current 6-digit code.
- Replies: Server `NOTICE` lines (secret + otpauth URI on `ENROLL`; status/confirmation otherwise).
- Errors: IRCv3 `FAIL TOTP` with `ACCOUNT_REQUIRED`, `TEMPORARILY_UNAVAILABLE`, `INSECURE_TRANSPORT` (ENROLL off TLS), `ALREADY_ENROLLED`, `NEED_MORE_PARAMS`, `INVALID_CODE`, `NO_PENDING`, `INVALID_SUBCOMMAND`.
- Example: `TOTP ENROLL` then `TOTP CONFIRM 492817`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` (`handleTotp`), `src/daemon/totp_auth.zig`

## LOGOUT

- Syntax: `LOGOUT`
- Description: Removes the account login, removes the live session from the session registry, sends account-notify, and revokes `+o` when oper status came from the account.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_LOGGEDOUT 901` when an account binding was cleared, optional `MODE <nick> :-o`, then server `NOTICE` confirming logout.
- Errors: None specific.
- Example: `LOGOUT`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig`

## DROP

- Syntax: `DROP <account> <password>`
- Description: Deletes an account after password verification.
- Privileges: Registered client.
- Parameters: Account and password.
- Replies: Server `NOTICE` confirming drop.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_PASSWDMISMATCH 464`, IRCv3 `FAIL DROP TEMPORARILY_UNAVAILABLE`.
- Example: `DROP alice correct-horse`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig`, `src/daemon/services.zig`

## RESETPASS

- Syntax: `RESETPASS <account>` (request) or `RESETPASS <account> <code> <new-password>` (set).
- Description: Reset a forgotten password by proving ownership of the account's verified email — the "other method" companion to the cert-verified one-argument `SETPASS`. The request form emails a one-time code (32 hex chars, 15-minute TTL) to the account's verified address; the set form consumes the code, sets the new password, and revokes existing session tokens. Usable while logged out.
- Privileges: Any registered connection (no login required).
- Requirements: A configured mail transport (`[mail]`); the account must have a **verified** email. Without `[mail]`, the request form replies `FAIL RESETPASS UNAVAILABLE`.
- Anti-abuse: The request form replies identically whether or not the account exists or has a verified email (no account enumeration), and will not re-send while a code issued within the last 60s is still pending.
- Replies: Request → `NOTICE` "if that account has a verified email, a reset code has been sent."; set → raw `RESETPASS SUCCESS <account> :Password reset; log in with your new password`.
- Errors: `ERR_NEEDMOREPARAMS 461`; IRCv3 `FAIL RESETPASS` with `TEMPORARILY_UNAVAILABLE`, `UNAVAILABLE`, `NO_REQUEST`, `EXPIRED`, `BAD_CODE`, `TOO_MANY_ATTEMPTS`, `INVALID_PASSWORD`.
- Example: `RESETPASS alice` then `RESETPASS alice 0123456789abcdef0123456789abcdef new-correct-horse`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` `handleResetpass`, `src/daemon/password_reset.zig`

## ACCOUNTINFO

- Syntax: `ACCOUNTINFO [account]`, `ACCOUNTINFO LOGINS [account]`, and `ACCOUNTINFO SESSIONS [account]`
- Description: Reports account name and flags, including `passkey_only` and `oper_stepup`. Without an argument, uses the caller's logged-in account. `LOGINS` lists up to eight recent sign-ins (time in milliseconds, mechanism, TLS, and an 8-byte prefix). `SESSIONS` lists live attachments on this process: nick, TLS or clear, and node id. The words `LOGINS` and `SESSIONS` are subcommands. A caller reads their own rows. An operator may name another account. The address, the certificate, and the session token are not shown.
- Privileges: Registered client. Another account's login or session rows require an operator.
- Parameters: Optional account. For `LOGINS` and `SESSIONS`, an optional account after the subcommand.
- Replies: Server `NOTICE` `account=<name> flags=<n> suspended=<bool> forbidden=<bool> noexpire=<bool> passkey_only=<bool> oper_stepup=<bool>`. Login rows are `LOGINS: time=<ms> mechanism=<name> tls=<clear|tls|unknown> prefix=<text|->`, or `LOGINS: none`. Session rows are `SESSIONS: nick=<nick> tls=<tls|clear> node=<id>`, `SESSIONS: none`, or `SESSIONS: truncated` after a full cap.
- Errors: `ERR_NEEDMOREPARAMS 461` when neither argument nor login exists; `ERR_NOPRIVILEGES 481` when a non-operator names another account's logins or sessions; `FAIL ACCOUNTINFO ACCOUNT_UNKNOWN`; `FAIL ACCOUNTINFO BAD_ACCOUNT`; `FAIL ACCOUNTINFO TEMPORARILY_UNAVAILABLE`.
- Example: `ACCOUNTINFO alice`, `ACCOUNTINFO LOGINS`, and `ACCOUNTINFO SESSIONS`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig`, `src/daemon/services.zig`

## SASLINFO

- Syntax: `SASLINFO`
- Description: Shows configured SASL mechanisms and whether the caller is currently logged in. Live mechanism listings are limited to mechanisms wired on this connection: `PLAIN`, `EXTERNAL`, `SCRAM-SHA-256`, `SCRAM-SHA-512`, `SCRAM-SHA-512-PLUS` when the TLS exporter is present, `SESSION-TOKEN`, `OAUTHBEARER`, and `ANONYMOUS`. The SASL router also parses `SCRAM-SHA-256-PLUS`, but current advertised CAP/SASLINFO/IRCX lists do not include it.
- Privileges: Registered client.
- Parameters: None.
- Replies: Server notices.
- Errors: None specific.
- Example: `SASLINFO`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig`, `src/daemon/dispatch.zig`, `src/proto/sasl_mechrouter.zig`

## SASL AUTHENTICATE and numerics

- Syntax: `AUTHENTICATE <mechanism|payload|*>`
- Description: IRCv3 SASL runs through the `AUTHENTICATE` dispatcher. It supports configured `PLAIN`, `EXTERNAL`, `SCRAM-SHA-256`, `SCRAM-SHA-512`, `SCRAM-SHA-512-PLUS`, `SESSION-TOKEN`, `OAUTHBEARER`, and `ANONYMOUS` mechanisms on the live connection. The router can parse `SCRAM-SHA-256-PLUS`, but that name is not currently advertised by CAP, SASLINFO, or IRCX package lists. `SESSION-TOKEN` is a SASL re-entry credential, distinct from the `SESSION TOKEN` / `SESSION MTOKEN` reclaim tokens used with `SESSION RESUME`.
- Replies: `AUTHENTICATE +` or challenge data during the exchange; `RPL_LOGGEDIN 900` plus `RPL_SASLSUCCESS 903` on success; optional final SCRAM verifier before success.
- Errors and numerics: `ERR_SASLFAIL 904`, `ERR_SASLTOOLONG 905`, `ERR_SASLABORTED 906`, `ERR_SASLALREADY 907`, and `RPL_SASLMECHS 908` before `904` for an unsupported mechanism. `RPL_LOGGEDOUT 901` is emitted when aborting an already-authenticated SASL exchange or on `LOGOUT`. The current dispatcher defines `900`, `901`, and `903`; it does not define or emit a `902` account-auth numeric.
- Account-status lockout: A SUSPENDED or FORBIDDEN account is rejected at the SASL success chokepoint for every non-guest mechanism, including SCRAM and OAUTHBEARER. The user-facing IRCv3 surface is the generic `904 :SASL authentication failed`, so account status is not enumerated.
- Sources: `src/daemon/dispatch.zig`, `src/daemon/server.zig`, `src/daemon/services.zig`

## ACCOUNTSET

- Syntax: `ACCOUNTSET <account> <password> <email|flags|secure|enforce> <value>`
- Description: Updates account settings after password verification. `email` sets the address; `flags` sets the non-privileged numeric flag bits; `secure on|off` recognizes the account only via identify, never an access-list match alone; `enforce on|off` controls nick protection on the account's registered nick (on by default — `off` opts the account out of the automatic force-rename sweep).
- Privileges: Registered client (the account owner).
- Parameters: Account, password, field, value.
- Replies: Server `NOTICE` confirming update.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_PASSWDMISMATCH 464`, `FAIL ACCOUNTSET INVALID_VALUE`, `INVALID_FIELD`, `PRIVILEGED_FLAGS`, `TEMPORARILY_UNAVAILABLE`.
- Example: `ACCOUNTSET alice correct-horse secure on`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig`, `src/daemon/services.zig`

## RECOVER

- Syntax: `RECOVER <nick>`
- Description: Forces an unauthenticated holder off the account owner's registered nick immediately, rather than waiting out the protection grace, then briefly holds the nick (nick-delay) so the owner can reclaim it. The requester must be identified to the account that owns the nick. A holder that is the owner's own authenticated session is never ejected. The pure `svc_recover` module owns the decision logic.
- Privileges: Registered client identified to the owning account.
- Parameters: Target nick.
- Replies: Server `NOTICE`; the holder is force-renamed to a `Guest…` nick.
- Errors: `ERR_NEEDMOREPARAMS 461`, `FAIL RECOVER NICK_NOT_REGISTERED`, `FAIL RECOVER ACCESS_DENIED`, `FAIL RECOVER TEMPORARILY_UNAVAILABLE`.
- Example: `RECOVER alice`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` `handleRecover`, `src/daemon/svc_recover.zig`

## RELEASE

- Syntax: `RELEASE <nick>`
- Description: Drops a server-held nick reservation (nick-delay) on the account owner's registered nick ahead of its window, making the nick available again. Requires identification to the account.
- Privileges: Registered client identified to the owning account.
- Parameters: Target nick.
- Replies: Server `NOTICE`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `FAIL RELEASE NICK_NOT_REGISTERED`, `FAIL RELEASE ACCESS_DENIED`, `FAIL RELEASE TEMPORARILY_UNAVAILABLE`.
- Example: `RELEASE alice`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` `handleRelease`, `src/daemon/svc_recover.zig`

## GHOST

- Syntax: `GHOST <nick> <password>`
- Description: Password-verifies the caller's logged-in account and disconnects a different live session only when the target nick is logged in to that same account.
- Privileges: Registered client logged in to an account.
- Parameters: Target nick and password.
- Replies: Victim receives `ERROR :Ghosted by <nick>`; caller receives server `NOTICE`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_PASSWDMISMATCH 464`, `FAIL GHOST TEMPORARILY_UNAVAILABLE`, `ACCOUNT_REQUIRED`, `NICK_NOT_OWNED`.
- Example: `GHOST alice_ correct-horse`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig`, `src/daemon/services.zig`

## CHANNEL

- Syntax: `CHANNEL <REGISTER|DROP|INFO|ACCESS|AKICK|SET|TRANSFER> <#channel> ...`
- Description: Real server command for channel services. The switch handles `REGISTER`, `DROP`, `INFO`, `ACCESS`, `AKICK`, `TRANSFER`, and `SET` for `MLOCK`, `KEEPTOPIC`, `TOPICLOCK`, `GUARD`, `PRIVATE`, `DESC`, and `URL`. `TRANSFER` moves the founder to an existing account. Any other parsed `SET` field replies that it is not available yet.
- Privileges: Registered client logged in to an account.
- Parameters: Subcommand and channel-specific arguments.
- Replies: Server notices; `REGISTER`/`DROP` also reflect live registered-channel state.
- Errors: IRCv3 `FAIL CHANNEL` codes including `TEMPORARILY_UNAVAILABLE`, `NEED_MORE_PARAMS`, `ACCOUNT_REQUIRED`, `INVALID_PARAMS`, `CHANNEL_EXISTS`, `CHANNEL_UNKNOWN`, `ACCESS_DENIED`, `BAD_CHANNEL_NAME`.
- Example: `CHANNEL REGISTER #zig`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig`

## CS

- Syntax: `CS <subcommand> <#channel> ...`
- Description: Alias of `CHANNEL`, dispatched to the same handler.
- Privileges: Same as `CHANNEL`.
- Parameters: Same as `CHANNEL`.
- Replies: Same as `CHANNEL`.
- Errors: Same as `CHANNEL`.
- Example: `CS INFO #zig`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig`

## SESSION

Syntax:

```irc
SESSION LIST
SESSION LIST MESH
SESSION TOKEN
SESSION MTOKEN
SESSION RESUME <credential>
SESSION DROP <#n|sid=<32-hex>>
SESSION REVOKE group=<32-hex>
```

The caller must be a registered client authenticated to the owning account.
`TOKEN` reveals the current local resume credential; composite issuance can return
`srm2l.<group>.<attachment>` instead of the bare logical 32-hex token. `MTOKEN`
returns a portable credential with `expires=<unix-seconds>`; composite `srm2m`
exact-restore issuance binds destination to issuer and another node can REDIRECT.
These are separate from the durable `sst_...` account-login credential issued by
`SESSIONTOKEN`. Parsing a sealed envelope does not authorize arbitrary-node
physical restore. See [credential domains](../credential-domains.md) for every
issuer/verifier, TTL and destination rule.

Legacy logical resume can add a sibling without consuming the group or disconnecting
existing clients; composite exact restore selects retained physical attachment
authority. All paths check account, current state, expiry/revocation and the exact
credential kind. A failed exact restore cannot silently become a fresh attachment.
The EXTERNAL account/nick compatibility lookup is separately possession-gated.

Local LIST reports this node's physical attachment inventory with opaque SIDs and
connection-bound `#n` selections. DROP compares the exact emitted row identity,
rejects stale/recycled/ambiguous selectors and refuses the caller's current row.
The live cross-reactor path uses `session_drop_tx.Journal` and owner reservations;
backpressure or an uncompleted transaction can return a temporary result rather
than allowing a foreign reactor to mutate a socket directly. Logical identity
must remain online while a surviving sibling owns it.

`LIST MESH` and group REVOKE use separate account-scoped mesh authority. The group
ID is not a local DROP SID. Completion requires signed durable-denial receipts
from the validated full roster/activation epoch; pending is neither success nor
rollback. Unsupported durable storage/full-roster support returns `UNSUPPORTED`.
Poll from another authenticated attachment if the selected group includes this
connection. Unrelated groups and SASL account-token credentials are independent.
See [the wire supplement](../protocol/onyx-session-control.v1.json).

`FAIL SESSION INVALID_TOKEN` and `NO_SESSION` report credential/origin failure.
Exact composite restore also returns `SESSION_REVOKED`, `NO_ATTACHMENT`, or
`ATTACHMENT_IN_USE`. The last means the selected physical attachment is active:
the credential can still be valid, no sibling is created, and no automatic
WARN/TOKEN-preservation hook runs. Do not infer invalidity or consumption from
`FAIL` alone. See the [complete reply table](../../design/session-resume-anywhere-blueprint.md#reply-and-retry-contract).

DROP selector errors include `INVALID_INDEX`, `AMBIGUOUS_SID`, `STALE_LIST` and
`CANNOT_DROP_CURRENT`. Retryable RESUME warnings use `ORIGIN_UNREACHABLE` or
`TEMPORARILY_UNAVAILABLE`. After those WARN results or a redirect, the immediate
next TOKEN request is suppressed once with `RESUME_CREDENTIAL_PRESERVED` so
clients do not overwrite stored state. An additional explicit TOKEN request
selects the current attachment's credential. Legacy logical-session attachment
to a live sibling remains distinct from busy exact physical restore.

Example: authenticate the same account, send `SESSION RESUME <stored>`, process
success/retry/redirect, then deliberately request fresh state only when appropriate.
Keep all credentials private. Cold restart account-login recovery does not restore
the old TCP attachment. Source: `sessions.zig`, `session_drop_tx.zig`, the SESSION
handlers in `server.zig`, and [the living session contract](../../design/session-resume-anywhere-blueprint.md).

## CERTADD

- Syntax: `CERTADD`
- Description: Binds the TLS client-certificate fingerprint presented on this connection to the logged-in account for future SASL EXTERNAL use.
- Privileges: Registered client logged in to an account with client certificate.
- Parameters: None.
- Replies: Server notice confirming fingerprint binding.
- Errors: `FAIL CERTADD TEMPORARILY_UNAVAILABLE`, `NOT_LOGGED_IN`, `NO_CLIENT_CERT`, `CERT_ADD_FAILED`.
- Example: `CERTADD`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig`, `src/daemon/services.zig`

## CERTLIST

- Syntax: `CERTLIST`
- Description: Lists TLS client-certificate fingerprints bound to the logged-in account for SASL EXTERNAL.
- Privileges: Registered client logged in to an account.
- Parameters: None.
- Replies: Server notices, one `CERTLIST <fingerprint>` per bound fingerprint, or a no-fingerprints notice.
- Errors: `FAIL CERTLIST TEMPORARILY_UNAVAILABLE`, `NOT_LOGGED_IN`, `CERT_LIST_FAILED`.
- Example: `CERTLIST`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig`

## CERTDEL

- Syntax: `CERTDEL <fingerprint>`
- Description: Removes a TLS client-certificate fingerprint binding from the logged-in account.
- Privileges: Registered client logged in to an account.
- Parameters: Certificate fingerprint.
- Replies: Server notice confirming removal.
- Errors: `FAIL CERTDEL TEMPORARILY_UNAVAILABLE`, `NOT_LOGGED_IN`, `NEED_MORE_PARAMS`, `CERT_NOT_OWNED`, `CERT_NOT_FOUND`, `CERT_DEL_FAILED`.
- Example: `CERTDEL SHA256:...`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig`

## KEYTRANS

- Syntax: `KEYTRANS [STATUS|ROOT|PROOF <position>]`
- Description: Inspects the account credential transparency log. `STATUS` (default) reports whether the log is enabled plus the current append count and Merkle Mountain Range root. `ROOT` is an alias for status. `PROOF <position>` streams an inclusion-proof snapshot for a leaf index as `KEYTRANS PROOF`, `KEYTRANS PATH`, `KEYTRANS PEAK`, and `KEYTRANS PROOF-END` server notices.
- Privileges: Registered client.
- Parameters: Optional subcommand; `PROOF` additionally takes a decimal leaf index.
- Replies: Server notices: `KEYTRANS STATUS disabled`, `KEYTRANS STATUS enabled entries=<n> root=<hex>`, or proof lines with root/path/peak hashes.
- Errors: `FAIL KEYTRANS TEMPORARILY_UNAVAILABLE`, `NEED_MORE_PARAMS`, `BAD_POSITION`, `DISABLED`, `NO_SUCH_LEAF`, `INTERNAL_ERROR`, `INVALID_SUBCOMMAND`.
- Example: `KEYTRANS PROOF 42`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` `handleKeyTrans`, `src/daemon/services.zig` `keyTransparencyProof`

## E2EEKEY

- Syntax: `E2EEKEY [STATUS|LIST [account]|ADD <device-id> <algorithm> <public-key>|DEL <device-id>]`
- Description: Manages public E2EE device-key advertisements for the caller's logged-in account. Device records are stored as account-scoped user PROP metadata under `e2ee.device.<device-id>` with value `<algorithm>:<public-key>`, so they replicate over the signed `ENTITY_PROP` path. `LIST [account]` reads public device keys for the caller or a named account; `ADD` and `DEL` require login to the owning account.
- Privileges: Registered client; account login required for `STATUS`, `ADD`, `DEL`, and caller-default `LIST`.
- Parameters: Optional subcommand; `ADD` takes a bounded device id, algorithm token, and public key token.
- Replies: Server notices: `E2EEKEY STATUS account=<account> devices=<n>`, `E2EEKEY DEVICE account=<account> id=<device> alg=<algorithm> key=<public-key>`, `E2EEKEY END account=<account> devices=<n>`, `E2EEKEY ADDED ...`, or `E2EEKEY DELETED ...`.
- Errors: `FAIL E2EEKEY NOT_LOGGED_IN`, `NEED_MORE_PARAMS`, `BAD_DEVICE`, `BAD_KEY`, `STORE_FAILED`, `INVALID_SUBCOMMAND`.
- Example: `E2EEKEY ADD phone mls-x25519 abcd+/=`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` `handleE2eeKey`, `src/proto/e2ee_policy.zig`

## IDENTITY

- Syntax: `IDENTITY [STATUS|LIST [account]|ADD <label> <ed25519-pubkey-hex> <signature-hex>|DEL <label>|VERIFY <account> <label> <ed25519-pubkey-hex> <signature-hex>]`
- Description: Manages portable account identity keys. `ADD` requires the caller to be logged in and stores a public Ed25519 key only after verifying that the key signed Onyx Server's account-binding transcript for the logged-in account and label. Stored records are account-scoped user PROP metadata under `identity.key.<label>` with value `<pubkey-hex>:<signature-hex>`, so the assertion replicates over signed `ENTITY_PROP`. `VERIFY` checks a supplied assertion without mutating state.
- Privileges: Registered client; account login required for `STATUS`, `ADD`, `DEL`, and caller-default `LIST`.
- Parameters: Optional subcommand; `ADD` takes a bounded label, 64-hex Ed25519 public key, and 128-hex Ed25519 signature.
- Replies: Server notices: `IDENTITY STATUS account=<account> keys=<n>`, `IDENTITY KEY account=<account> label=<label> pub=<hex> sig=<hex>`, `IDENTITY END account=<account> keys=<n>`, `IDENTITY VERIFY ... result=<valid|invalid>`, `IDENTITY ADDED ...`, or `IDENTITY DELETED ...`.
- Errors: `FAIL IDENTITY NOT_LOGGED_IN`, `NEED_MORE_PARAMS`, `BAD_ASSERTION`, `BAD_LABEL`, `STORE_FAILED`, `INVALID_SUBCOMMAND`.
- Example: `IDENTITY ADD primary <64-hex-pubkey> <128-hex-signature>`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` `handleIdentity`, `src/proto/account_identity.zig`

## RECOVERYCODES

- Syntax: `RECOVERYCODES STATUS | GENERATE [password] | CLEAR [password] | LOGIN <account> <code>`
- Description: Generates a replacement set of single-use account recovery codes, reports the remaining count, clears the set, or consumes one code to log in without a password or TOTP. Generated codes are shown once as `XXXXX-XXXXX` and are never listed again. `GENERATE` requires TLS; the optional password re-checks the logged-in account.
- Privileges: `STATUS`, `GENERATE`, and `CLEAR` require a logged-in account; `LOGIN` is usable while logged out.
- Replies: Notices with the count/codes or `RECOVERYCODES: login ok`; consumed codes are immediately spent.
- Errors: `FAIL RECOVERYCODES ACCOUNT_REQUIRED`, `INSECURE_TRANSPORT`, `AUTH_FAILED`, `NEED_MORE_PARAMS`, `INVALID_SUBCOMMAND`, and temporary/internal store errors.
- Example: `RECOVERYCODES GENERATE` then `RECOVERYCODES LOGIN alice ABCDE-FGHJK`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig`, `src/daemon/services.zig` recovery-code store

## SETPASS

- Syntax: `SETPASS <current-password> <new-password>` or, on a client-certificate-verified connection, `SETPASS <new-password>`
- Description: Changes the logged-in account password. The one-argument form is a recovery path permitted only after SASL EXTERNAL proved a client certificate bound to that account. New passwords must satisfy the normal account policy and differ from the current password.
- Privileges: Registered client logged in to an account; certificate recovery additionally requires the bound TLS client certificate.
- Replies: `NOTICE` confirming the password change/reset.
- Errors: `FAIL SETPASS ACCOUNT_REQUIRED`, `WRONG_PASSWORD`, `INVALID_PASSWORD`, `RESET_NOT_AUTHORIZED`, or `TEMPORARILY_UNAVAILABLE`.
- Example: `SETPASS old-correct-horse new-correct-horse`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` (`handleSetpass`)

## SUCCESSOR

- Syntax: `SUCCESSOR <#channel> SHOW | SET <account> | CLEAR`
- Description: Reads or sets the registered channel founder's successor. `SHOW` returns the armed successor. `SET` of a different account waits 10 minutes before it replaces that name; `CLEAR` during the wait cancels the replacement and leaves the armed successor. A drop during the wait still hands the channel to the armed successor. The first successor is held the same way, so it cannot take the channel in that window. After the hold, a drop promotes the successor `SHOW` returns and then clears the stored successor. `SET` and `CLEAR` are founder-only unless the caller is an oper.
- Privileges: Registered client for `SHOW`; channel founder or oper for `SET`/`CLEAR`.
- Replies: Notices describing the current, changed, or cleared successor.
- Errors: `FAIL SUCCESSOR ACCOUNT_UNKNOWN`, `NOT_FOUNDER`, `INVALID_VALUE`, `INVALID_SUBCOMMAND`, `NEED_MORE_PARAMS`, or temporary account-store errors.
- Example: `SUCCESSOR #zig SET alice`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` (`handleSuccessor`)

## ACCOUNT

- Syntax: `ACCOUNT <SUSPEND|UNSUSPEND|FORBID|UNFORBID|NOEXPIRE|INFO> <account> [on|off]`
- Description: Operator account-lifecycle administration. Suspension and forbiddance block account authentication at the shared SASL success gate; `NOEXPIRE` toggles expiry exemption; `INFO` returns the complete lifecycle flags.
- Privileges: Oper with the narrower `service_admin` privilege.
- Replies: `NOTICE` containing the action, account, registration state, and resulting flags.
- Errors: `ERR_NOPRIVILEGES 481`, `FAIL ACCOUNT ACCOUNT_UNKNOWN`, `BAD_ACCOUNT_NAME`, `INVALID_VALUE`, `NEED_MORE_PARAMS`, or temporary store errors.
- Example: `ACCOUNT SUSPEND alice`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` (`handleAccountAdmin`)

## SESSIONTOKEN

- Syntax: `SESSIONTOKEN`
- Description: Issues a short-lived account-authentication token for SASL `SESSION-TOKEN`. This credential authenticates the account on a later connection; it does not select or reclaim another live `SESSION` attachment.
- Privileges: Registered client logged in to an account over TLS.
- Replies: `NOTICE SESSIONTOKEN <account> <token> expires=<unix-seconds>`.
- Errors: `FAIL SESSIONTOKEN INSECURE_TRANSPORT`, `NOT_LOGGED_IN`, `TOKEN_ISSUE_FAILED`, or temporary account-store errors.
- Example: `SESSIONTOKEN`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` (`handleSessionToken`)

## WEBAUTHN

- Syntax: `WEBAUTHN STATUS | REGISTER [label] | REGISTER-FINISH <cred-id> <client-data-json> <authdata> [attestation] | AUTH <account> | AUTH-FINISH <cred-id> <client-data-json> <authdata> <signature> | LIST | REMOVE <cred-id> | RENAME <cred-id> :<label> | LOCK`
- Description: Passkey (WebAuthn) registration and passwordless login. `REGISTER`/`REGISTER-FINISH` bind a credential to the logged-in account; `AUTH`/`AUTH-FINISH` issue and verify a single-use challenge; `LIST`, `REMOVE`, `RENAME`, and `STATUS` manage that account's credentials. `LOCK` refuses password, PLAIN, and SCRAM until a recovery code replaces the password, revokes SASL session tokens, and arms `oper_stepup`. It requires a passkey that is already stored. While that latch is set, a password, SCRAM, recovery-code, or session-token session does not become a network operator. A passkey or EXTERNAL session may. Recovery that replaces the password clears `passkey_only` and leaves the latch set until a later passkey sign-in. `ACCOUNTSET` cannot set or clear either bit. Attestation and user-verification requirements follow `[webauthn]` configuration.
- Privileges: Registration, management, and `LOCK` require a logged-in account; authentication challenge may name an account while logged out. All ceremonies require a configured WebAuthn relying party and fail closed on malformed base64, origin, RP-ID, credential, or signature data.
- Replies: `WEBAUTHN` challenge/allow-credential lines, status/list notices, `WEBAUTHN LOCKED :password login disabled`, and a normal account login notice after a successful assertion.
- Errors: `FAIL WEBAUTHN NOT_CONFIGURED`, `NOT_LOGGED_IN`, `NO_PENDING`, `BAD_CREDENTIAL_ID`, `BAD_CLIENT_DATA`, `BAD_AUTHDATA`, `BAD_SIGNATURE`, `BAD_ORIGIN`, `RP_MISMATCH`, `ASSERTION_FAILED`, `UNKNOWN_CREDENTIAL`, `CREDENTIAL_ACCOUNT_MISMATCH`, `PASSKEY_REQUIRED`, `INVALID_SUBCOMMAND`, and policy/temporary errors.
- Example: `WEBAUTHN REGISTER phone`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` (`handleWebauthn`), `src/crypto/webauthn.zig`, `src/daemon/webauthn_creds.zig`

## E2EEGROUP

- Syntax: `E2EEGROUP <#channel> <KEY-PACKAGE|COMMIT|WELCOME> <from-device> [to-account] [to-device] :<opaque-payload>` (operator control: `E2EEGROUP STATUS|ON|OFF`)
- Description: Relays bounded opaque group-E2EE control records without decrypting or placing payload material in history. Local authoring is fail-closed behind account login, IRCX, `onyx/e2ee`, reusable-session, channel membership, device ownership, and the live peer-capability barrier. `WELCOME` additionally requires the target account/device to be present.
- Privileges: Logged-in account with the required capabilities; `STATUS`/`ON`/`OFF` require oper control and `E2EEGROUP ON` is refused until current-capable peers meet the activation barrier.
- Replies: Exact bounded control-line delivery to eligible attachments; `WARN E2EEGROUP AUTHORING_QUIESCED` or temporary warnings when custody/delivery cannot be staged.
- Errors: `FAIL E2EEGROUP NOT_LOGGED_IN`, `IRCX_REQUIRED`, `CAP_REQUIRED`, `BAD_CHANNEL`, `BAD_KIND`, `BAD_DEVICE`, `BAD_ACCOUNT`, `BAD_PAYLOAD`, `NOT_ON_CHANNEL`, `DEVICE_NOT_OWNED`, `TARGET_UNAVAILABLE`, or `ORIGIN_REJECTED`.
- Example: `E2EEGROUP #team COMMIT dev-a :<base64url-record>`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` (`handleE2eeGroup`), `src/proto/e2ee_group_control.zig`, `src/substrate/undertow/e2ee_group_relay.zig`

## RECOGNIZE

- Syntax: `RECOGNIZE ADD <mask> | DEL <mask> | LIST`
- Description: Manages the logged-in account's soft host-recognition masks. A matching unauthenticated nick keeps its protected nick past the grace period but receives no account privileges until SASL authenticates.
- Privileges: Logged-in account owner.
- Replies: Notices for list entries and add/delete outcomes.
- Errors: `ERR_NOPRIVILEGES 481`, `ERR_NEEDMOREPARAMS 461`, invalid-mask/list-full notices, or temporary account-service errors.
- Example: `RECOGNIZE ADD *!*@trusted.example`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` (`handleRecognize`)

## LISTCHANS

- Syntax: `LISTCHANS`
- Description: Lists every registered channel for which the logged-in account has a durable access grant, including the access level, then emits an end marker with the count.
- Privileges: Logged-in account.
- Replies: `NOTICE LISTCHANS <#channel> <level>` and `End of LISTCHANS (n)`.
- Errors: `ERR_NOPRIVILEGES 481` when not identified or temporary account-service errors.
- Example: `LISTCHANS`
- Sources: `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` (`handleListchans`)

## WEBHOOK

- Syntax: `WEBHOOK CREATE <#channel> [name] | LIST <#channel> | DELETE <id>`
- Description: Creates and manages Discord-compatible incoming webhook bindings. The create response contains the secret URL once; list output never reveals the token. Channel operators and network opers may manage bindings, subject to configured per-channel/network limits.
- Privileges: Channel operator or oper for each named channel.
- Replies: Notices with the one-time URL, non-secret metadata, or deletion result.
- Errors: `ERR_NEEDMOREPARAMS 461`, channel/operator errors, disabled-feature notice, limit errors, or invalid channel/id notices.
- Example: `WEBHOOK CREATE #alerts bridge`
- Sources: `src/daemon/modules/webhook.zig`, `src/daemon/server.zig` (`handleWebhook`)

## WEBPUSH

- Syntax: `WEBPUSH SUBSCRIBE <endpoint> <p256dh> <auth> | WEBPUSH UNSUBSCRIBE <endpoint> | WEBPUSH LIST`
- Description: Stores up to three account-scoped browser Push API subscriptions. Endpoints must be HTTPS; `p256dh` and `auth` are the base64url-unpadded values returned by `PushSubscription.getKey()`. Delivery is best-effort and dead endpoints are pruned.
- Privileges: Logged-in account; the worker must be enabled on the node.
- Replies: Notices for stored/removed endpoints and list count.
- Errors: `FAIL WEBPUSH DISABLED`, `ACCOUNT_REQUIRED`, `NEED_MORE_PARAMS`, `INVALID_ENDPOINT`, `INVALID_KEY`, `TOO_MANY_SUBSCRIPTIONS`, `NOT_SUBSCRIBED`, or `INVALID_SUBCOMMAND`.
- Example: `WEBPUSH SUBSCRIBE https://push.example/sub <p256dh-b64url> <auth-b64url>`
- Sources: `src/daemon/modules/feature_misc.zig`, `src/daemon/server.zig` (`handleWebpush`), `src/daemon/webpush.zig`

## MEMO

- Syntax: `MEMO [LIST|CLEAR|SEND <account> :message|FORWARD [<account>|OFF|NONE]|IGNORE [ADD|DEL|LIST] [<account>]]`
- Description: Onyx Server offline account messages keyed by recipient account. A direct message left for an account with no attached session is stored in the local memo mailbox and delivered when that account next logs in (`REGISTER` / `IDENTIFY` / SASL). `LIST` is the default subcommand and does not clear; login delivery clears pending messages. `SEND` stores for a known account, follows the recipient's forward chain when set, and silently drops when the recipient ignores the sender (success reply unchanged so the block cannot be probed). After a successful store, the node best-effort nudges local Web Push and broadcasts a secured `MEMO_PUSH` hint to mesh peers.
- Privileges: Registered client; account login required for every subcommand.
- Parameters: Optional subcommand. `SEND` takes a target account and message body. `FORWARD` with no target reports the current forward; `OFF`/`NONE` clears it. `IGNORE ADD|DEL` takes a blocked-sender account; bare `IGNORE`/`IGNORE LIST` lists entries.
- Replies: Server notices — `MEMO from <from> :<text>`, `MEMO: End of offline memos (<n>)`, clear/forward/ignore confirmations, and `MEMO: message stored for delivery` (or `… (forwarded to <account>)`). Clear/forward mutations also publish on the Event Spine service plane.
- Errors: `ERR_NEEDMOREPARAMS 461`, `FAIL MEMO ACCOUNT_REQUIRED`, `ACCOUNT_UNKNOWN`, `MAILBOX_FULL`, `INVALID_MESSAGE`, `TEMPORARILY_UNAVAILABLE`, `INVALID_SUBCOMMAND`, `FORWARD_CYCLE`, `INVALID_ACCOUNT`.
- Example: `MEMO SEND alice :ping me later`
- Sources: `src/daemon/modules/feature_misc.zig`, `src/daemon/server.zig`, `src/daemon/memo.zig`

## VHOST

- Syntax: `VHOST [LIST|USE <name>|OFF|CLAIM <host>|REQUEST <host>|OFFERLIST|APPROVE <account>|DENY <account> [:reason]|OFFER <template> [:label]|SET <account> <host> [name]|<host>]`
- Description: Manages visible host personas. Bare `VHOST` lists the wardrobe and offers. Users can request, claim, use, or turn off personas. Opers can approve/deny requests, publish offers, set account personas, or set their own host with bare `VHOST <host>`. Applying a vhost broadcasts native `CHGHOST` to capable common-channel peers; `CHGHOST` itself is not a registered command.
- Privileges: Registered client for list/use/off/claim/request/offerlist; account login required for persona actions; oper required for approve/deny/offer/set/bare host set.
- Parameters: Subcommand-specific.
- Replies: Server notices; native `CHGHOST` lines to capable clients when a host changes.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`, `FAIL VHOST ACCOUNT_REQUIRED`, `INVALID_HOST`, `TEMPORARILY_UNAVAILABLE`; other validation failures as notices.
- Example: `VHOST REQUEST staff.example`
- Sources: `src/daemon/modules/feature_misc.zig`, `src/daemon/server.zig`

## PRIVS

- Syntax: `PRIVS`
- Description: Reports the caller's live operator class and privilege set.
- Privileges: Oper.
- Parameters: None.
- Replies: `RPL_PRIVS 270`.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `PRIVS`
- Sources: `src/daemon/modules/feature_misc.zig`, `src/daemon/server.zig`

## FILTER

- Syntax: `FILTER <ADD|DEL|LIST> [pattern]`
- Description: Oper-only content filter control. Patterns are case-insensitive substring blocks applied to non-oper messages.
- Privileges: Oper.
- Parameters: `LIST`, or `ADD`/`DEL` plus pattern.
- Replies: Server notices for list/end output and mutation confirmations.
- Errors: `ERR_NOPRIVILEGES 481`, `ERR_NEEDMOREPARAMS 461`, `FAIL FILTER TEMPORARILY_UNAVAILABLE`, `INVALID_PATTERN`, `NO_SUCH_PATTERN`, `INVALID_SUBCOMMAND`.
- Example: `FILTER ADD badword`
- Sources: `src/daemon/modules/feature_misc.zig`, `src/daemon/server.zig`

## SEEN

- Syntax: `SEEN <account>`
- Description: Reports an account's last seen and last login timestamps plus recent login/logout history recorded by account login/logout hooks.
- Privileges: Registered client (`services.ext` sets `.access = .registered`).
- Parameters: Account name.
- Replies: Server notices with summary and recent records, or `SEEN <account>: no record`.
- Errors: `ERR_NEEDMOREPARAMS 461`.
- Example: `SEEN alice`
- Sources: `src/daemon/modules/services_ext.zig`, `src/daemon/server.zig`
