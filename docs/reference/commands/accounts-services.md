# Accounts and services commands

*Account, service, and persona commands exposed as real server commands — Onyx Server has no pseudo-clients.*

The `accounts` module registers the account and service commands (`src/daemon/modules/accounts.zig:125`, `src/daemon/modules/accounts.zig:155`), with additional commands from feature and service modules. Onyx Server services are real server commands that reply through raw server lines and server notices; these handlers do not model pseudo-clients (`src/daemon/server.zig:22987`, `src/daemon/server.zig:23472`).

## REGISTER

- Syntax: `REGISTER <account|*> <email|*> <password>`
- Description: Registers an account immediately and logs the session in. `*` uses the current nick as the account name. When mail is configured and an email is supplied, the verification code is sent out of band and the client gets a notice telling it to run `VERIFY <code>`; the code is not shown in-band. Registration applies SASL-account oper elevation when configured, tracks the session, delivers pending memos, applies autojoin, and emits welcome and client-registration side effects.
- Privileges: Registered client.
- Parameters: Account, email or `*`, password.
- Replies: Raw `REGISTER SUCCESS <account> :Account registered`, optional email-status notice, welcome/account side effects.
- Errors: IRCv3 `FAIL REGISTER` with `TEMPORARILY_UNAVAILABLE`, `NEED_MORE_PARAMS`, `ACCOUNT_EXISTS`, `BAD_ACCOUNT_NAME`, `INVALID_PASSWORD`, `INVALID_EMAIL`, `ACCOUNT_FORBIDDEN`.
- Example: `REGISTER alice alice@example.net correct-horse`
- Sources: `src/daemon/modules/accounts.zig:125`, `src/daemon/server.zig:22832`, `src/daemon/server.zig:22965`

## VERIFY

- Syntax: `VERIFY [account] <code>`
- Description: Confirms a pending account email verification token.
- Privileges: Registered client.
- Parameters: Verification code, with an optional account name. The one-argument form verifies the caller's logged-in account.
- Replies: Server notice `VERIFY: your account email is now verified`, `VERIFY: nothing to verify for your account`, or IRCv3 `FAIL VERIFY`.
- Errors: `FAIL VERIFY ACCOUNT_REQUIRED`, `EXPIRED`, `INVALID_CODE`, `TOO_MANY_ATTEMPTS`; missing parameters produce a usage notice.
- Example: `VERIFY alice abcdef012345`
- Sources: `src/daemon/modules/accounts.zig:126`, `src/daemon/server.zig:15424`

## IDENTIFY

- Syntax: `IDENTIFY <account> <password> [<2fa-code>]`
- Description: Authenticates to an existing account and logs the session in. Performs derived oper elevation, tracks the session, delivers pending memos, applies autojoin, and emits login side effects. When the account has TOTP two-factor auth active (see `TOTP`), a valid 6-digit code is required as the third parameter; a correct password with a missing or wrong code is a failed login (and counts against the brute-force throttle).
- Privileges: Registered client.
- Parameters: Account, password, and — for 2FA accounts — the current TOTP code.
- Replies: Server `NOTICE` confirming login plus account-notify/welcome side effects.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_PASSWDMISMATCH 464`, IRCv3 `FAIL IDENTIFY TEMPORARILY_UNAVAILABLE`, `FAIL IDENTIFY TOTP_REQUIRED` (2FA code missing/incorrect).
- Example: `IDENTIFY alice correct-horse 492817`
- Sources: `src/daemon/modules/accounts.zig:127`, `src/daemon/server.zig:23072`, `src/daemon/services.zig:1140`

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
- Sources: `src/daemon/modules/accounts.zig:129`, `src/daemon/server.zig:23128`

## DROP

- Syntax: `DROP <account> <password>`
- Description: Deletes an account after password verification.
- Privileges: Registered client.
- Parameters: Account and password.
- Replies: Server `NOTICE` confirming drop.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_PASSWDMISMATCH 464`, IRCv3 `FAIL DROP TEMPORARILY_UNAVAILABLE`.
- Example: `DROP alice correct-horse`
- Sources: `src/daemon/modules/accounts.zig:130`, `src/daemon/server.zig:23169`, `src/daemon/services.zig:1158`

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

- Syntax: `ACCOUNTINFO [account]`
- Description: Reports account name and flags. Without an argument, uses the caller's logged-in account.
- Privileges: Registered client.
- Parameters: Optional account.
- Replies: Server `NOTICE` `account=<name> flags=<n> suspended=<bool> forbidden=<bool> noexpire=<bool>`.
- Errors: `ERR_NEEDMOREPARAMS 461` when neither argument nor login exists; `FAIL ACCOUNTINFO ACCOUNT_UNKNOWN`; `FAIL ACCOUNTINFO TEMPORARILY_UNAVAILABLE`.
- Example: `ACCOUNTINFO alice`
- Sources: `src/daemon/modules/accounts.zig:134`, `src/daemon/server.zig:23457`, `src/daemon/services.zig:1284`

## SASLINFO

- Syntax: `SASLINFO`
- Description: Shows configured SASL mechanisms and whether the caller is currently logged in. Live mechanism listings are limited to mechanisms wired on this connection: `PLAIN`, `EXTERNAL`, `SCRAM-SHA-256`, `SCRAM-SHA-512`, `SCRAM-SHA-512-PLUS` when the TLS exporter is present, `SESSION-TOKEN`, `OAUTHBEARER`, and `ANONYMOUS`. The SASL router also parses `SCRAM-SHA-256-PLUS`, but current advertised CAP/SASLINFO/IRCX lists do not include it.
- Privileges: Registered client.
- Parameters: None.
- Replies: Server notices.
- Errors: None specific.
- Example: `SASLINFO`
- Sources: `src/daemon/modules/accounts.zig:136`, `src/daemon/server.zig:23582`, `src/daemon/dispatch.zig:1418`, `src/proto/sasl_mechrouter.zig:16`

## SASL AUTHENTICATE and numerics

- Syntax: `AUTHENTICATE <mechanism|payload|*>`
- Description: IRCv3 SASL runs through the `AUTHENTICATE` dispatcher. It supports configured `PLAIN`, `EXTERNAL`, `SCRAM-SHA-256`, `SCRAM-SHA-512`, `SCRAM-SHA-512-PLUS`, `SESSION-TOKEN`, `OAUTHBEARER`, and `ANONYMOUS` mechanisms on the live connection. The router can parse `SCRAM-SHA-256-PLUS`, but that name is not currently advertised by CAP, SASLINFO, or IRCX package lists. `SESSION-TOKEN` is a SASL re-entry credential, distinct from the `SESSION TOKEN` / `SESSION MTOKEN` reclaim tokens used with `SESSION RESUME`.
- Replies: `AUTHENTICATE +` or challenge data during the exchange; `RPL_LOGGEDIN 900` plus `RPL_SASLSUCCESS 903` on success; optional final SCRAM verifier before success.
- Errors and numerics: `ERR_SASLFAIL 904`, `ERR_SASLTOOLONG 905`, `ERR_SASLABORTED 906`, `ERR_SASLALREADY 907`, and `RPL_SASLMECHS 908` before `904` for an unsupported mechanism. `RPL_LOGGEDOUT 901` is emitted when aborting an already-authenticated SASL exchange or on `LOGOUT`. The current dispatcher defines `900`, `901`, and `903`-`908`; it does not define or emit a `902` account-auth numeric.
- Account-status lockout: A SUSPENDED or FORBIDDEN account is rejected at the SASL success chokepoint for every non-guest mechanism, including SCRAM and OAUTHBEARER. The user-facing IRCv3 surface is the generic `904 :SASL authentication failed`, so account status is not enumerated.
- Sources: `src/daemon/dispatch.zig:169`, `src/daemon/dispatch.zig:1805`, `src/daemon/dispatch.zig:1833`, `src/daemon/dispatch.zig:1919`, `src/daemon/dispatch.zig:1979`, `src/daemon/dispatch.zig:2034`, `src/daemon/server.zig:20740`, `src/daemon/services.zig:2528`

## ACCOUNTSET

- Syntax: `ACCOUNTSET <account> <password> <email|flags|secure|enforce> <value>`
- Description: Updates account settings after password verification. `email` sets the address; `flags` sets the non-privileged numeric flag bits; `secure on|off` recognizes the account only via identify, never an access-list match alone; `enforce on|off` controls nick protection on the account's registered nick (on by default — `off` opts the account out of the automatic force-rename sweep).
- Privileges: Registered client (the account owner).
- Parameters: Account, password, field, value.
- Replies: Server `NOTICE` confirming update.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_PASSWDMISMATCH 464`, `FAIL ACCOUNTSET INVALID_VALUE`, `INVALID_FIELD`, `PRIVILEGED_FLAGS`, `TEMPORARILY_UNAVAILABLE`.
- Example: `ACCOUNTSET alice correct-horse secure on`
- Sources: `src/daemon/modules/accounts.zig:137`, `src/daemon/server.zig:24377`, `src/daemon/services.zig:1252`

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
- Sources: `src/daemon/modules/accounts.zig:138`, `src/daemon/server.zig:24427`, `src/daemon/services.zig:1242`

## CHANNEL

- Syntax: `CHANNEL <REGISTER|DROP|INFO|ACCESS|AKICK|SET|TRANSFER> <#channel> ...`
- Description: Real server command for channel services. The implemented switch handles `REGISTER`, `DROP`, `INFO`, `ACCESS`, `AKICK`, and `SET MLOCK`; `TRANSFER` and non-MLOCK `SET` fields are parsed but still reply as unavailable.
- Privileges: Registered client logged in to an account.
- Parameters: Subcommand and channel-specific arguments.
- Replies: Server notices; `REGISTER`/`DROP` also reflect live registered-channel state.
- Errors: IRCv3 `FAIL CHANNEL` codes including `TEMPORARILY_UNAVAILABLE`, `NEED_MORE_PARAMS`, `ACCOUNT_REQUIRED`, `INVALID_PARAMS`, `CHANNEL_EXISTS`, `CHANNEL_UNKNOWN`, `ACCESS_DENIED`, `BAD_CHANNEL_NAME`.
- Example: `CHANNEL REGISTER #zig`
- Sources: `src/daemon/modules/accounts.zig:69`, `src/daemon/server.zig:8709`

## CS

- Syntax: `CS <subcommand> <#channel> ...`
- Description: Alias of `CHANNEL`, dispatched to the same handler.
- Privileges: Same as `CHANNEL`.
- Parameters: Same as `CHANNEL`.
- Replies: Same as `CHANNEL`.
- Errors: Same as `CHANNEL`.
- Example: `CS INFO #zig`
- Sources: `src/daemon/modules/accounts.zig:70`, `src/daemon/server.zig:8714`

## SESSION

- Syntax: `SESSION [LIST|TOKEN|RESUME <token>|DROP <#n|sid=<32-hex>>]`
- Description: Lists account attachments, reveals credentials for this exact logical session, attaches the client to that session, or revokes one other physical attachment. `SESSION TOKEN` emits a 32-hex-character origin-local credential and, when mesh resume is enabled, a separately sealed portable credential. Both are reusable: every successful `RESUME` adds or restores an attachment without disconnecting siblings or consuming the credential. These are session credentials, not the `sst_...` account-authentication credential used by SASL `SESSION-TOKEN` / `SESSIONTOKEN`; authentication alone never selects another same-account session. `LIST` emits an opaque 128-bit `sid` for rows with a stable attachment ID and binds each `#n` to that connection's exact emitted snapshot. `DROP` compare-and-removes only that physical row: recycled indices, rotated token/signon/attachment identity, ambiguous SIDs, and the caller's current row fail closed. Same-token siblings retain their nick and merged channel modes without a false QUIT; dropping the final row emits the ordinary QUIT/offline transition. An attached target or surviving exact-token sibling owned by another reactor currently returns `TEMPORARILY_UNAVAILABLE` without mutating either connection, pending the reserved two-owner handoff protocol.
- Privileges: Registered client logged in to an account.
- Parameters: Optional subcommand; `LIST` is default.
- Replies: `NOTICE ... :SESSION TOKEN <hex>`, optional `NOTICE ... :SESSION MTOKEN <sealed-hex> expires=<unix-seconds>`, `SESSION LIST <*|-> #n signon=<ms> <attached|detached> [sid=<32-hex>]`, `SESSION: end of session list`, `SESSION DROP #n ok` / `SESSION DROP sid=<32-hex> ok`, successful `SESSION RESUME: already attached`, `attached to live session`, `attached to live mesh session`, `attached to replicated mesh session`, or `session restored`, plus redirects. A portable token is valid for 12 hours; its live snapshot is offered immediately and re-offered on secured-peer establishment/reconnect. All attachments share identity/channel state, receive events, and may participate.
- Retry behavior: `ORIGIN_UNREACHABLE` and `TEMPORARILY_UNAVAILABLE` retain the supplied credential. After either result or a redirect, the immediately following `SESSION TOKEN` is suppressed once with `WARN SESSION RESUME_CREDENTIAL_PRESERVED`, preventing a reconnecting client from overwriting its still-valid stored credential. Repeating `SESSION TOKEN` explicitly returns the credential for the current attachment. An already-live session is a successful attachment path, not `SESSION_ATTACHED`.
- Errors: Terminal `FAIL SESSION INVALID_TOKEN`, `INVALID_INDEX`, `NO_SESSION`, `NO_SUCH_SESSION`, `AMBIGUOUS_SID`, `STALE_LIST`, or `CANNOT_DROP_CURRENT`; retryable `WARN SESSION ORIGIN_UNREACHABLE`, `TEMPORARILY_UNAVAILABLE`, or `RESUME_CREDENTIAL_PRESERVED`; account-required notice.
- Example: `SESSION TOKEN`
- Sources: `src/daemon/modules/accounts.zig:143`, `src/daemon/server.zig:24958`, `src/daemon/server.zig:25007`, `src/daemon/services.zig:899`

## CERTADD

- Syntax: `CERTADD`
- Description: Binds the TLS client-certificate fingerprint presented on this connection to the logged-in account for future SASL EXTERNAL use.
- Privileges: Registered client logged in to an account with client certificate.
- Parameters: None.
- Replies: Server notice confirming fingerprint binding.
- Errors: `FAIL CERTADD TEMPORARILY_UNAVAILABLE`, `NOT_LOGGED_IN`, `NO_CLIENT_CERT`, `CERT_ADD_FAILED`.
- Example: `CERTADD`
- Sources: `src/daemon/modules/accounts.zig:145`, `src/daemon/server.zig:23640`, `src/daemon/services.zig:531`

## CERTLIST

- Syntax: `CERTLIST`
- Description: Lists TLS client-certificate fingerprints bound to the logged-in account for SASL EXTERNAL.
- Privileges: Registered client logged in to an account.
- Parameters: None.
- Replies: Server notices, one `CERTLIST <fingerprint>` per bound fingerprint, or a no-fingerprints notice.
- Errors: `FAIL CERTLIST TEMPORARILY_UNAVAILABLE`, `NOT_LOGGED_IN`, `CERT_LIST_FAILED`.
- Example: `CERTLIST`
- Sources: `src/daemon/modules/accounts.zig:150`, `src/daemon/server.zig:23653`

## CERTDEL

- Syntax: `CERTDEL <fingerprint>`
- Description: Removes a TLS client-certificate fingerprint binding from the logged-in account.
- Privileges: Registered client logged in to an account.
- Parameters: Certificate fingerprint.
- Replies: Server notice confirming removal.
- Errors: `FAIL CERTDEL TEMPORARILY_UNAVAILABLE`, `NOT_LOGGED_IN`, `NEED_MORE_PARAMS`, `CERT_NOT_OWNED`, `CERT_NOT_FOUND`, `CERT_DEL_FAILED`.
- Example: `CERTDEL SHA256:...`
- Sources: `src/daemon/modules/accounts.zig:151`, `src/daemon/server.zig:23669`

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

## MEMO

- Syntax: `MEMO [LIST|CLEAR|SEND <account> :message|FORWARD [<account>|OFF|NONE]|IGNORE [ADD|DEL|LIST] [<account>]]`
- Description: Onyx Server offline account messages keyed by recipient account. A direct message left for an account with no attached session is stored in the local memo mailbox and delivered when that account next logs in (`REGISTER` / `IDENTIFY` / SASL). `LIST` is the default subcommand and does not clear; login delivery clears pending messages. `SEND` stores for a known account, follows the recipient's forward chain when set, and silently drops when the recipient ignores the sender (success reply unchanged so the block cannot be probed). After a successful store, the node best-effort nudges local Web Push and broadcasts a secured `MEMO_PUSH` hint to mesh peers.
- Privileges: Registered client; account login required for every subcommand.
- Parameters: Optional subcommand. `SEND` takes a target account and message body. `FORWARD` with no target reports the current forward; `OFF`/`NONE` clears it. `IGNORE ADD|DEL` takes a blocked-sender account; bare `IGNORE`/`IGNORE LIST` lists entries.
- Replies: Server notices — `MEMO from <from> :<text>`, `MEMO: End of offline memos (<n>)`, clear/forward/ignore confirmations, and `MEMO: message stored for delivery` (or `… (forwarded to <account>)`). Clear/forward mutations also publish on the Event Spine service plane.
- Errors: `ERR_NEEDMOREPARAMS 461`, `FAIL MEMO ACCOUNT_REQUIRED`, `ACCOUNT_UNKNOWN`, `MAILBOX_FULL`, `INVALID_MESSAGE`, `TEMPORARILY_UNAVAILABLE`, `INVALID_SUBCOMMAND`, `FORWARD_CYCLE`, `INVALID_ACCOUNT`.
- Example: `MEMO SEND alice :ping me later`
- Sources: `src/daemon/modules/feature_misc.zig:61`, `src/daemon/server.zig:40648`, `src/daemon/server.zig:40655`, `src/daemon/memo.zig:4`

## VHOST

- Syntax: `VHOST [LIST|USE <name>|OFF|CLAIM <host>|REQUEST <host>|OFFERLIST|APPROVE <account>|DENY <account> [:reason]|OFFER <template> [:label]|SET <account> <host> [name]|<host>]`
- Description: Manages visible host personas. Bare `VHOST` lists the wardrobe and offers. Users can request, claim, use, or turn off personas. Opers can approve/deny requests, publish offers, set account personas, or set their own host with bare `VHOST <host>`. Applying a vhost broadcasts native `CHGHOST` to capable common-channel peers; `CHGHOST` itself is not a registered command.
- Privileges: Registered client for list/use/off/claim/request/offerlist; account login required for persona actions; oper required for approve/deny/offer/set/bare host set.
- Parameters: Subcommand-specific.
- Replies: Server notices; native `CHGHOST` lines to capable clients when a host changes.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481`, `FAIL VHOST ACCOUNT_REQUIRED`, `INVALID_HOST`, `TEMPORARILY_UNAVAILABLE`; other validation failures as notices.
- Example: `VHOST REQUEST staff.example`
- Sources: `src/daemon/modules/feature_misc.zig:49`, `src/daemon/server.zig:9734`, `src/daemon/server.zig:9982`

## PRIVS

- Syntax: `PRIVS`
- Description: Reports the caller's live operator class and privilege set.
- Privileges: Oper.
- Parameters: None.
- Replies: `RPL_PRIVS 270`.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `PRIVS`
- Sources: `src/daemon/modules/feature_misc.zig:50`, `src/daemon/server.zig:9709`

## FILTER

- Syntax: `FILTER <ADD|DEL|LIST> [pattern]`
- Description: Oper-only content filter control. Patterns are case-insensitive substring blocks applied to non-oper messages.
- Privileges: Oper.
- Parameters: `LIST`, or `ADD`/`DEL` plus pattern.
- Replies: Server notices for list/end output and mutation confirmations.
- Errors: `ERR_NOPRIVILEGES 481`, `ERR_NEEDMOREPARAMS 461`, `FAIL FILTER TEMPORARILY_UNAVAILABLE`, `INVALID_PATTERN`, `NO_SUCH_PATTERN`, `INVALID_SUBCOMMAND`.
- Example: `FILTER ADD badword`
- Sources: `src/daemon/modules/feature_misc.zig:51`, `src/daemon/server.zig:9647`

## SEEN

- Syntax: `SEEN <account>`
- Description: Reports an account's last seen and last login timestamps plus recent login/logout history recorded by account login/logout hooks.
- Privileges: Registered client (`services.ext` sets `.access = .registered`).
- Parameters: Account name.
- Replies: Server notices with summary and recent records, or `SEEN <account>: no record`.
- Errors: `ERR_NEEDMOREPARAMS 461`.
- Example: `SEEN alice`
- Sources: `src/daemon/modules/services_ext.zig:58`, `src/daemon/server.zig:7185`
