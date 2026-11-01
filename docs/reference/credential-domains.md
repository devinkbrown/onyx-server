# Credential domains

This is a source contract for the **0.9.0 source tree**, audited on
2026-10-26 and refreshed against the integrated W53 source on 2026-10-29,
then re-based on 2026-11-01. The recorded production image is now
**0.9.0+066d9b8356be-dirty** on both nodes; confirm deployment separately against
[the runtime paths record](../ops/onyx-server-paths.md). Tests linked below are
source evidence, not a new test run or release acceptance receipt. The W52 and
W53 recovery/storage corrections have separate focused Debug/Safe receipts in
the [wave execution record](../ops/roadmap-wave-execution-2026-10-26.md); they do
not establish a green full suite for the current candidate.

Credentials with similar names are not interchangeable. An account credential
establishes an account; a resume credential selects retained session authority;
a node signature authenticates a particular statement; a media key authenticates
one transport purpose. Authentication still needs the receiving domain's
account, trust, lifecycle, and revocation checks.

## Client session and account credentials

| Family | Issuer and verifier | Scope and time contract |
| --- | --- | --- |
| `SESSION TOKEN` | SessionStore creates a random 16-byte group token; authenticated `SESSION TOKEN` reveals the existing handle. `SESSION RESUME` resolves it under the caller's account. | Reusable local logical-session credential; several physical attachments can share it. The local row has no embedded expiry timestamp. Its validity depends on retained row/lifecycle authority, not the account-token TTL. |
| `srm2l.<group>.<attachment>` | The same local issuer wraps the group token and stable nonzero 16-byte physical attachment ID. Strict envelope decoder separates this from mesh authority. | Exact physical restore selector plus local bearer credential. The attachment ID alone is not the credential. No new lifetime is introduced by wrapping. |
| `SESSION MTOKEN`, legacy SRM1 | Issuer HMAC-seals account, session ID, origin placement, wall-clock issue/expiry, and fresh nonce using configured `mesh_pass`; receiver opens the canonical sealed bytes and applies reclaim policy. | Portable reclaim/redirect credential, not SASL login. Daemon issuance is 12 hours; fields are milliseconds, displayed `expires=` is Unix seconds. SRM1 codec accepts exactly-at-expiry and rejects strictly later times. |
| `srm2m.<sealed>.<attachment>`, SRM2 | Issuer signs an attachment claim; the live receiver verifies it and restores only at the issuer or redirects. Envelope decoding alone does not verify the signature. | Signed account/group/AID/origin/destination/kind/time/nonce authority. Current exact-restore issuance binds destination to issuer; another node cannot restore a same-token local row. Default claim maximum is 12 hours in milliseconds. Destination countersignatures and consume replay/conflict handling exist separately in the codec and are not activated by this live path. |
| `SESSIONTOKEN`, SASL `SESSION-TOKEN` (`sst_…`) | Account Services issues 16 random bytes encoded as `sst_` plus 32 lowercase hex characters. SASL callback validates account name, current durable binding, hash, account status, and expiry. | Account-login continuation, independent of attachment resume. Default TTL is 30 days in **Unix seconds**; rejected when `expires_unix <= now_unix`. Reissue rotates the account's current token. |

Local identity and issuance: [sessions.zig:23](../../src/daemon/sessions.zig#L23),
[row contract:165](../../src/daemon/sessions.zig#L165),
[random minting:1912](../../src/daemon/sessions.zig#L1912),
[authenticated command dispatch:53048](../../src/daemon/server.zig#L53048),
[TOKEN rendering:53103](../../src/daemon/server.zig#L53103), and
[resume dispatch:53280](../../src/daemon/server.zig#L53280).
Composite issuance is configurable and defaults off; do not infer the envelope
from client capability alone
([Config:2516](../../src/daemon/server.zig#L2516)).
The [envelope codec:18](../../src/proto/session_resume_credential.zig#L18)
requires canonical field structure and rejects zero credentials/AIDs.

Portable issuance and clocks are in
[server.zig:51529](../../src/daemon/server.zig#L51529),
[SRM1 issuer:51562](../../src/daemon/server.zig#L51562), and
[SRM2 issuer:51599](../../src/daemon/server.zig#L51599).
The [SRM1 opener:240](../../src/proto/session_reclaim_mesh.zig#L240)
checks integrity and time. Current live SRM1 resumes are reusable within their
TTL ([live reclaim handler:53526](../../src/daemon/server.zig#L53526)). The
[replay ring:310](../../src/proto/session_reclaim_mesh.zig#L310) supports legacy
consume handling; it does not make those current resumes one-shot
([legacy convergence:54832](../../src/daemon/server.zig#L54832)). SRM2's codec uses distinct
`onyx-session-reclaim-attachment-claim-v2` and
`onyx-session-reclaim-attachment-consume-v2` signature domains and distinguishes
`create_new` from `exact_restore`
([codec:30](../../src/proto/session_reclaim_attachment.zig#L30)). The live
[exact-reclaim handler:53450](../../src/daemon/server.zig#L53450) verifies the
claim and trusted route, then restores locally or redirects; it does not call
the codec's countersigned consume or replay-store admission. Codec replay and
conflict tests therefore do not establish those live guarantees. Physical
identity and claim kind remain separate: an exact restore cannot silently
fall through to creating another attachment.

Treat local tokens, sealed mesh credentials, and their wrappers as secrets.
The raw reusable token exists in private SessionStore/Helix state, and signed
replicas can contain it: a signature provides integrity, not encryption.
Use protected client signaling and secured mesh transport; never log credential
bytes. The local command entry shown above checks account authentication; it
does **not** establish a universal TLS-only transport policy. In contrast,
[account-token issuance:48520](../../src/daemon/server.zig#L48520) explicitly
requires `conn.is_tls` and obtains Unix wall time before rotating credentials.
Account-token persistence stores SHA-256 token digests and the current-account
binding, not the plaintext token
([Services:2644](../../src/daemon/services.zig#L2644));
[validation:2707](../../src/daemon/services.zig#L2707) refuses orphan records,
expired tokens, suspended/forbidden accounts, and passkey-only accounts.

Relevant tests:
[account issue/hash/expiry:6603](../../src/daemon/services.zig#L6603),
[orphan-record refusal:6625](../../src/daemon/services.zig#L6625),
[actual account command/cold reopen:102004](../../src/daemon/server.zig#L102004),
[non-TLS refusal:102085](../../src/daemon/server.zig#L102085),
[SRM2 codec vectors:591](../../src/proto/session_reclaim_attachment.zig#L591),
[time boundaries:752](../../src/proto/session_reclaim_attachment.zig#L752), and
[physical replay isolation:790](../../src/proto/session_reclaim_attachment.zig#L790).

## Signed replica statements and permanent denials

These are authenticated mesh records, not client account-login bearer tokens.
The node signs canonical bytes; the receiver must separately authorize the
signer/origin against configured trust, enforce revision/replay rules, and apply
account binding. The token embedded in a record remains secret.

The current token-family codec has separate offer, ACK, and attachment-lease
Ed25519 contexts
([session_replica.zig:47](../../src/daemon/helix/session_replica.zig#L47)).
Frozen operations 1/2 remain upsert/remove; operation 3 carries explicit signed
`resume_eligible`. False means inventory-only, with empty nick/restore snapshot;
metadata, a positive lease, or an ACK cannot promote it into remote resume
authority. Operation 4 is a terminal logical-group revoke. See
[canonical validation:550](../../src/daemon/helix/session_replica.zig#L550) and
[eligibility regression:6825](../../src/daemon/helix/session_replica.zig#L6825).
The separate SRA3 physical-attachment family has its own offer/ACK/revoke/lease
contexts; its version/capability negotiation does not authorize another family
([session_replica_attachment.zig:32](../../src/daemon/helix/session_replica_attachment.zig#L32)).

Daemon offers use the 12-hour wall-clock horizon; positive attachment leases are
90 seconds, renewed every 30 seconds. Store library defaults differ from daemon
configuration and are not an issuance promise
([daemon configuration:6290](../../src/daemon/server.zig#L6290),
[lease contract:51529](../../src/daemon/server.zig#L51529),
[Store defaults:835](../../src/daemon/helix/session_replica.zig#L835)).
Typed ACK 8 is current group-fence enforcement readiness, **not** physical
inventory completeness; ACK 9 acknowledges durable group denial. Both bind
membership epoch and full roster digest. Daemon readiness receipts last 90
seconds; other group receipts last 30 seconds, with expiry checked before
coverage is counted
([receipt admission:52732](../../src/daemon/server.zig#L52732),
[issuance:52766](../../src/daemon/server.zig#L52766)).

A retained group-denial fact is permanent even after its signed transport
expiry: no newer offer/lease, account spelling change, GC, or replay may clear
it. First canonical signed fact remains immutable. Persistence uses the
existing private account OroStore namespace and a BLAKE3-derived token key;
the value is signed wire containing private account/token data
([durable adapter:35](../../src/daemon/session_group_revoke_durable.zig#L35),
[write-once commit:68](../../src/daemon/session_group_revoke_durable.zig#L68)).
Retired-signing authority is an exact `(group_key, issuer_key, fact_digest)` pin,
not permission to accept new signatures from that retired key. Required groups
must survive both cold restore and Helix verification
([authorization:95](../../src/daemon/session_group_revoke_durable.zig#L95),
[restore:128](../../src/daemon/session_group_revoke_durable.zig#L128),
[retained verification:158](../../src/daemon/session_group_revoke_durable.zig#L158)).
The retirement fact digest has a separate fixed domain; these digests/public
keys are exportable identifiers, not bearer credentials.

Relevant tests:
[permanent fence/OOM staging:6397](../../src/daemon/helix/session_replica.zig#L6397),
[durable ambiguity:319](../../src/daemon/session_group_revoke_durable.zig#L319),
[exact retired pins:401](../../src/daemon/session_group_revoke_durable.zig#L401),
[missing required facts:490](../../src/daemon/session_group_revoke_durable.zig#L490).

## Media credentials

Candidate physical endpoint issuance requires the actual caller's membership,
original routing owner, and protected signaling custody. Host candidates,
stream IDs, codec advertisements, or a capability label do not prove membership
or possession. Logical JOIN alone creates no MAC key/UDP offer
([caller gate:58736](../../src/daemon/server.zig#L58736),
[logical JOIN:70789](../../src/daemon/server.zig#L70789)).

Current native endpoint `NATIVE-MACKEY` reveals a private 32-byte master via the
protected caller reply. It derives four keys bound to the issued nonzero stream:
client→server/server→client frame and feedback purposes have different HMAC
labels. Neither a master-direct tag nor the opposite direction's key is valid
ingress authority
([capability derivation:4](../../src/substrate/media_capability.zig#L4),
[actual secret rendering:71132](../../src/daemon/server.zig#L71132),
[ingress regression:3149](../../src/daemon/native_media_transport.zig#L3149)).
The older `(channel,participant)` derived MAC lane remains separately present
([legacy derivation:248](../../src/substrate/cadence_frame.zig#L248)); do not
substitute that key for a current physical endpoint master.
Browser `MACKEY` is also caller-only protected signaling output
([issuer:58441](../../src/daemon/server.zig#L58441)); it is not a session credential.

ICE ufrag/password authenticate endpoint STUN checks; ufrag is a lookup name,
password is secret. Allocation rotates old endpoint indexes, and STUN
MESSAGE-INTEGRITY verifies against the selected endpoint password
([allocation:370](../../src/substrate/media_transport.zig#L370),
[verification:582](../../src/substrate/media_transport.zig#L582)).
The WebRTC advertisement supplies either a DTLS certificate fingerprint or,
for the SDES path, the secret SRTP group key; the two modes are checked
separately
([current renderer:71114](../../src/daemon/server.zig#L71114)).
A fingerprint is a public certificate binding requiring possession/handshake
verification, not a bearer key. No universal wall-clock media credential TTL
is defined by these codec/issuance seams: use endpoint lifetime, replacement,
teardown, and strict owner-bound Helix carry. Repeated authenticated feedback
is allowed; MAC validity alone is explicitly **not freshness/replay protection**
([media_capability.zig:43](../../src/substrate/media_capability.zig#L43)).

Relevant tests:
[directional actual workers:3408](../../src/daemon/native_media_transport.zig#L3408),
[protected output rollback:143394](../../src/daemon/server.zig#L143394),
[plaintext browser JOIN refusal:144436](../../src/daemon/server.zig#L144436).

## TLS resumption tickets

A TLS ticket is transport-resumption authority, separate from account
`SESSIONTOKEN` and logical-session `SESSION RESUME` credentials. The sealed
server ticket contains suite, PSK, nonce, issue time, lifetime, age adjustment
and early-data limits; it contains no Onyx account, logical-session token or
client-certificate identity. The client stored-session envelope also contains
the PSK and must be treated as sensitive credential material
([ticket fields](../../src/crypto/tls_resumption.zig#L39),
[client envelope](../../src/crypto/tls_resumption.zig#L58)).

The daemon defaults resumption off and the early-data grant to zero. When
enabled, its connections use process current/previous ticket keys and a shared
replay guard; source capture/adoption preserves this state through Helix.
These mechanisms do not establish cross-node ticket-key sharing or prove a
particular deployed configuration. The advertised lifetime is capped at seven
days. The live daemon supplies a clock for sealed-lifetime checks; generic
engine callers without a clock have different limits. Client ticket age is
caller-supplied, so codec checks do not prove an external client's persistent
store expires credentials correctly
([live configuration](../../src/daemon/server.zig#L8130),
[acceptance checks](../../src/crypto/tls_server.zig#L2384),
[client ticket loading](../../src/crypto/tls_client.zig#L905)).

Ordinary 1-RTT resumption tickets remain reusable. The bounded 2,048-entry
binder replay ring applies to accepted 0-RTT, not to all ticket use; eviction
and freshness limits prevent interpreting it as universal, permanent replay
protection. A rejected early-data attempt can still resume with 1-RTT.
After HRR, an incompatible exact ticket suite now falls back to a full
handshake with the committed suite. That transport fallback does not itself
issue, rotate or revoke an application session credential
([replay guard](../../src/crypto/tls_resumption.zig#L79),
[HRR ticket decline](../../src/crypto/tls_server.zig#L2393)).

Certificate collection has a separate continuity gap. Current source exposes
optional `request_client_cert`, accepts an empty certificate, and skips
certificate collection on PSK resumption. Tickets do not restore a certificate
identity. IRC and WS share ticket-key scope, and previous keys can remain
accepted through Helix. This is not evidence of bypassing a mandatory mTLS
mode: no such `require_client_cert` policy exists in the current source.
CERTFP is derived from the current proven certificate, and SASL EXTERNAL
requires a nonnull fingerprint and account binding; a ticket alone cannot
supply either. Full-handshake recovery and a future identity/policy-bound
ticket design remain integration work
([optional request](../../src/crypto/tls_server.zig#L208),
[resumed certificate path](../../src/crypto/tls_server.zig#L1231),
[EXTERNAL gate](../../src/proto/sasl_mechrouter.zig#L258)).

## Account factors and operator authority

Account passwords are reusable knowledge credentials; their stored authority has
no credential TTL and remains subject to replacement/removal and account
lifecycle policy. SCRAM's fresh nonce/challenge and conversation proof are a
separate replay domain: the stored verifier is not a reusable conversation
proof. A persistent CERTFP account binding likewise has no binding TTL; explicit
certificate removal revokes that mapping. Certificate validity/peer policy and
proof of the private key are separate from the public fingerprint. These
lifecycles are implemented by password update and certificate binding/removal in
[services.zig](../../src/daemon/services.zig); a fingerprint alone supplies no
bearer authority.

Passwords, certificate possession, continuation tokens, recovery, and passkeys
are different authentication factors. Account password verification uses salted
PBKDF2-HMAC-SHA256 and timing-safe comparison; SCRAM has a separate verifier
store. CERTADD binds certificate fingerprints to an account; EXTERNAL needs the
TLS client certificate and verified binding, not a hostname or client-supplied
fingerprint text
([password verifier:5459](../../src/daemon/services.zig#L5459),
[SCRAM/cert companions:569](../../src/daemon/services.zig#L569),
[certificate binding:2160](../../src/daemon/services.zig#L2160),
[actual mutual-TLS test:114552](../../src/daemon/server.zig#L114552)).

There is **no OPER password credential**: OPER is disabled; configured operator
status is projected from the authenticated account. Passkey/recovery policy can
require a live passkey or EXTERNAL factor, excluding password/session-token
sessions. Reauthentication replaces prior authority before recomputation
([OPER handler:931](../../src/daemon/oper_cmd.zig#L931),
[factor gate:47043](../../src/daemon/server.zig#L47043),
[projection:47073](../../src/daemon/server.zig#L47073)).

Signed operator grants bind account, privilege bits, class/title, issuer,
incarnation, issue time, and expiry; they are mesh assertions rather than
client bearer passwords. Legacy grant verification rejects
`now_ms >= expiry_ms`
([oper_cred_share.zig:48](../../src/proto/oper_cred_share.zig#L48),
[verification:235](../../src/proto/oper_cred_share.zig#L235)).
OCG2 uses `ONYX-OPER-GRANT-v2\0`, a maximum 24-hour grant TTL in milliseconds,
and its own revision/replay model; its codec/durable image does not alone prove
live activation. The live projection still explicitly consumes the sealed
live-config binding; durable facts do not independently elevate a session
([OCG2:255](../../src/proto/oper_cred_share.zig#L255),
[authority image:22](../../src/daemon/durable_oper_authority.zig#L22),
[projection seam:47092](../../src/daemon/server.zig#L47092)).

## Email verification and password-reset codes

Both live flows generate 16 random bytes and encode 32 lowercase hexadecimal
characters. They authorize different operations and are not session-resume
credentials. Issuance requires the configured mail path; knowing an account name
alone does not supply either code.

Email verification uses `VERIFY [account] <code>` and binds the code to the
account's pending email. Services persists a `V1|account|email|token|issued_ms`
record before mirroring the pending request in RAM. That record carries the
original secret; its encoding alone does not establish backing-store encryption.
Success consumes the pending record, and reissue replaces it. The lifetime is
15 minutes in milliseconds, with expiry at elapsed time **greater than or equal
to** the TTL. RAM secret storage is wiped when removed.

The live durable path has an explicit policy gap: `.bad_token` returns before
RAM verification's five-attempt accounting, and the durable record has no attempt
counter. Do not describe the live durable flow as enforcing that RAM limit.
Sources: [verification store](../../src/daemon/account_verify.zig),
[durable verification](../../src/daemon/services.zig), and `handleVerify` /
verification issuance in [server.zig](../../src/daemon/server.zig).

Password reset uses `RESETPASS <account> <code> <new-password>` and mails the
verified account address. Its RAM record defaults to 15 minutes in milliseconds;
expiry uses elapsed time **strictly greater than** the TTL. Issuance has a
60-second resend cooldown; replacement invalidates the old code. Five incorrect
attempts return `bad_token`, and the sixth removes the record. Removal securely
wipes the secret.

The live handler checks the code, admits the password/SCRAM/session-authority
change, then consumes the code under one World lock. Invalid-password or
allocation rejection retains the same code and its attempt count for retry;
accepted commit consumes it once. Ambiguous storage I/O poisons account storage
and blocks further authentication until recovery. Reset codes remain RAM-only:
this does not promise that a code survives a cold recovery or makes the code
itself part of the durable password transaction.
Sources: [password_reset.zig](../../src/daemon/password_reset.zig), `handleResetpass`
and the transactional RESETPASS test in [server.zig](../../src/daemon/server.zig).

## Bot grants

`BOTGRANT` requires an IRC operator with `server_admin`. It creates a server-side
authorization record for an account, one channel and one action (`speak`,
`webhook` or `history`); it is neither a bearer token nor an operator credential.
TTL input is positive seconds, converted with overflow checks to realtime
milliseconds. Expiry at or before the current time rejects the grant; `DEL`
revokes it. Bounds are 256 bots, 256 grants, and 64 bytes each for account/scope.

Helix's `BGNT` v1 image carries this table. Presence is optional: a missing image
adopts an empty table, while recognized malformed, duplicate or noncanonical
images abort. Do not call it a mandatory current family. Sources:
[bot_grant_snapshot.zig](../../src/daemon/helix/bot_grant_snapshot.zig) and
`handleBotGrant` / bot-grant adoption in [server.zig](../../src/daemon/server.zig).

## TLS delegated credentials and inactive migration codec

TLS delegated credentials are signed public credentials for a separately held
secret delegated private key. The TLS library supports optional TLS 1.3
presentation when the client offers extension 34 and compatible schemes. The
server signature domain is `TLS, server delegated credentials`. Expiry is leaf
certificate `notBefore + valid_time` seconds; validation requires a clock,
remaining lifetime no more than seven days, and expiry strictly before leaf
`notAfter`. Expiry occurs when current time is greater than credential expiry.
The seven-day bound concerns remaining lifetime, not raw `valid_time`.

No daemon configuration assignment was found for this library option. The CLI
inspects/validates existing credentials and does not mint them; these source
paths do not establish an enabled daemon credential workflow. Sources:
[delegated_credential.zig](../../src/proto/delegated_credential.zig),
[tls_client.zig](../../src/crypto/tls_client.zig),
[tls_server.zig](../../src/crypto/tls_server.zig), and
[delegated_credential_cli.zig](../../src/daemon/delegated_credential_cli.zig).

The separate internal [Helix migration codec](../../src/daemon/helix/migration_token.zig)
HMAC-SHA256 signs canonical account, source/destination node, issued/expiry
millisecond and nonce claims, without an added domain string. Destination and
nonce are authenticated, but `verify` itself neither compares an expected
destination nor consumes/revokes a nonce. Only its export was found outside the
codec; this is an inactive library mechanism, distinct from live local, SRM1 and
SRM2 migration/session authorization. Its signing key is secret. Activation would
need the missing caller policy, not merely a successful codec verification.

## WebAuthn, recovery codes and TOTP

WebAuthn uses a 32-byte random, unpadded-base64url public challenge; it is freshness
input, not a bearer credential. Pending state belongs to the connection and
ceremony, with an AUTH account or REGISTER label. Expiry is elapsed time greater
than five minutes in milliseconds. FINISH consumes the challenge before proof
validation, after initial argument/login checks. AUTH checks the challenge,
origin, RP ID, stored credential account, signature, presence, configured user
verification and authenticator-counter regression. REGISTER uses the currently
logged-in account at FINISH; legacy three-argument registration accepts raw
authenticator data, and attestation requirements are configurable. Do not infer
an identical signature/attestation policy across those registration paths.
Sources: [webauthn_creds.zig](../../src/daemon/webauthn_creds.zig) and the PASSKEY
handlers in [server.zig](../../src/daemon/server.zig).

A durable passkey credential is an account-bound public-key record for an
authenticator-created keypair; its private key stays with the authenticator.
`Services.WebauthnCredential` records creation time but no credential expiry.
The binding remains until account-scoped deletion or account lifecycle
invalidation; repeated possession proofs use fresh AUTH challenges rather than
consuming the stored public key. See account-scoped credential storage/`webauthnDelete` and the
credential record in [services.zig](../../src/daemon/services.zig).

Recovery codes are ten generated secrets of ten characters from a 32-symbol
alphabet, displayed once over TLS as `XXXXX-XXXXX`. Login strips hyphens and
uppercases. Storage contains SHA-256 digests binding the lowercase account and
code under `onyx-recovery-v1|`, not the original secrets. No expiry is recorded;
generation replaces the set, and a successful LOGIN consumes a digest before
finishing login. This does not establish an atomic login/consumption boundary.
CLEAR reports success only after Services accepts deletion. A storage failure
returns failure and retains the live code set; ambiguous I/O preserves the
existing poisoned-storage recovery requirement. Sources:
[services.zig](../../src/daemon/services.zig) and `handleRecoveryCodes` in
[server.zig](../../src/daemon/server.zig).

TOTP enrollment generates a 32-symbol Base32 shared secret and displays it over
TLS. Confirmation persists the active secret; defaults are HMAC-SHA1, six digits,
30-second Unix-time steps and a ±one-step window. The module rejects the last
accepted step and older steps. That replay counter is RAM state: restoring an
absent active enrollment resets it. Normal verification does not reset it; the
live loader first checks whether the enrollment is already present/pending.
Durable or mesh-wide replay continuity is not established by this RAM guard.
Disable removes enrollment; confirmation/removal also update durable policy and
session-token revocation. Sources: [totp_auth.zig](../../src/daemon/totp_auth.zig)
and TOTP/loading handlers in [server.zig](../../src/daemon/server.zig).

## OAuth, Web Push and TURN

SASL OAUTHBEARER accepts an external issuer's reusable signed JWT when the daemon
has configured verification policy. The verifier requires the selected algorithm,
validates the signature and requires `exp`; issuer/audience restrictions are
optional configured constraints. Account mapping defaults to `sub`, and a supplied
authzid must match it. Expiry uses Unix seconds and rejects `now > exp`, accepting
equality. The verifier itself has no nonce-consumption or token-revocation ledger;
that is distinct from account/session authority checks elsewhere. Sources:
[oauth_jwt.zig](../../src/daemon/oauth_jwt.zig),
[sasl_mechrouter.zig](../../src/proto/sasl_mechrouter.zig) and OAuth wiring in
[server.zig](../../src/daemon/server.zig).

A Web Push subscription supplies an HTTPS endpoint, 65-byte P-256 public key and
16-byte `auth` secret for the logged-in account, with up to three subscriptions.
The persistent list contains encoded key/secret data and no subscription-expiry
field. Treat the endpoint as sensitive too: it may contain capability material.
Add, replacement and unsubscribe mutations use strict storage reads and writes.
Malformed stored lists and allocation, encoding or write failures withhold
success and preserve prior live subscriptions. The loader checks the three-row
bound, endpoint validity and duplicate endpoints before mutation. Ambiguous I/O
still requires storage recovery. Separately, VAPID signs a
JWT for the push-service origin with a twelve-hour Unix-seconds expiry; message
TTL is also twelve hours. These are not subscription lifetimes. Sources:
[webpush.zig](../../src/daemon/webpush.zig) and WEBPUSH/storage handlers in
[server.zig](../../src/daemon/server.zig).

The daemon's `MEDIA TURN` path returns `TURN_CUT` and allocates no relay credential.
The separate [TURN parser](../../src/substrate/turn.zig) is an inactive framing
library; a 96-bit STUN transaction ID is request correlation, not bearer
authorization. See [media_cmd.zig](../../src/daemon/media_cmd.zig). This does not
establish an external relay deployment or a working constrained-network call.

## Public selectors and remaining inventory

AID, client/fd identity, nick, node ID/public key, hostname, SID, group selector,
and page cursor are not interchangeable bearer credentials. SID is a
one-way domain-separated derivation from token+AID; group selector has a
separate derivation. DROP/REVOKE still require authenticated account-scoped
resolution. LIST ordinals and opaque mesh cursors depend on their connection's
cached account/generation/lifetime; they are not transferable resume authority
([SID:198](../../src/daemon/session_sid.zig#L198),
[group selector:402](../../src/daemon/session_sid.zig#L402),
[mesh paging:52905](../../src/daemon/server.zig#L52905)).
Capability negotiation enables a format/operation; it does not authenticate an
account, establish configured-root membership, or prove complete inventory.

The setup CLI's `review_id` is not a bearer credential. It is a fresh public
correlation value for one held preparation in one local process. A headless
controller returns it with an explicit publish/cancel acknowledgement after
reviewing the actual material. Another invocation rejects it; it grants no IRC,
session, operator or mesh authority and is not stored as a reusable session
token. Private custody digests are never part of that public review. See the
[setup review contract](../guide/setup.md).

This source inventory is not full token-roadmap completion. A bounded end-to-end
transport-policy audit for legacy local SESSION credentials, complete media
freshness/rekey policy, cross-node factor replay/consumption boundaries, and
recovery revocation/admission behavior remain explicit gaps. The inventories
above distinguish active handlers, library-only options, inactive codecs and
public selectors; they do not infer stronger guarantees from signatures,
TLS-capability advertisement or codec existence.
