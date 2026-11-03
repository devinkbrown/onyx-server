# Automation, policy and abuse commands

These commands are declared in the enabled `feature.misc` and `oper.security`
modules. Registration in the command table does not make every feature enabled:
handler authority, current configuration and live stores still apply. Sources:
[feature_misc.zig](../../../src/daemon/modules/feature_misc.zig),
[oper_security.zig](../../../src/daemon/modules/oper_security.zig), and the named
`LinuxServer.handle*` functions in [server.zig](../../../src/daemon/server.zig).
Replies are server NOTICEs unless a numeric/standard failure is stated below.

## POLICY

`POLICY [LIST|ROLLBACK]` is operator-only. The list reports the current ward,
filter, class and ban generations. `ROLLBACK` restores the retained last policy
undo, audits the action, and reports the resulting generation. It reports
`nothing to roll back` or `rollback failed` when appropriate; this is not a
configuration-file history or arbitrary historical-generation restore service.
Source: `handlePolicy`, `rollbackPolicy`, `commitPolicy`.

## OUTHOOK

`OUTHOOK ADD <url> <secret> <categories>`, `OUTHOOK DEL <url>`, and `OUTHOOK LIST`
require an operator with `server_admin`. Categories select Event Spine events.
The list shows URLs and categories and excludes the secret. Private, loopback
and link-local destinations are refused unless the explicit private-target
policy allows them. This is outbound event delivery; inbound Discord-compatible
`WEBHOOK` bindings are a separate command and listener. Never put a real signing
secret in shared logs or examples. Source: `handleOutboundWebhook` and the
outbound webhook worker in `server.zig`.

## BOTGRANT

`BOTGRANT ADD <account> <speak|webhook|history> <channel> <ttl-seconds>`,
`BOTGRANT DEL <account> <kind> <channel>`, and `BOTGRANT LIST [account]` require
an operator with `server_admin`. A grant is account-, scope-, kind- and time-bound;
it marks the account as a bot without granting operator authority. Lists show
live expiry metadata. A signature authenticates the grant statement; the live
store, expiry and revocation checks still authorize each use.
Source: `handleBotGrant`, `bot_grant_snapshot.zig`; see
[credential domains](../credential-domains.md#bot-grants).

## BOTCMD

`BOTCMD ADD <name> <argc> :<help>`, `BOTCMD RUN <name> [args...]`, and
`BOTCMD LIST` require an authenticated account with a current speak grant. Commands
are stored under that account, and RUN requires exactly the declared argument
count. The current handler validates the registration/invocation and returns a
`BOTCMD ok` notice; it does not execute shell programs, install UI buttons, or
implement arbitrary remote bot execution. Source: `handleBotCmd`, `botHasSpeakGrant`
and `src/daemon/slash_cmd.zig`.

## DEFER

```irc
DEFER AT <unix-ms> <#channel> :<text>
DEFER CRON <min> <hour> <dom> <mon> <dow> <#channel> :<text>
DEFER AT <unix-ms> OPER <#channel> <flag>
```

A registered client can schedule a channel message; operator mode scheduling
requires the handler's operator authority. The five-field cron and absolute
Unix-millisecond forms are validated before scheduling. Authority checks are
currently admission-time checks. At due time, a message needs its saved memo/body
and a still-existing channel; it is emitted locally with the saved nickname and
`@deferred` prefix, without rechecking account membership, bans or later authority
revocation. A scheduled mode can likewise run after the scheduler loses operator
authority. Jobs are marked fired before output; this is not a retained MESSAGE_V2
transaction, a retry guarantee or exact-once mesh delivery. For example, a user
who schedules a message and then PARTs or is banned can still have that job fire
if another user keeps the channel alive. Account revocation must not be assumed
to cancel queued work. Storage and capacity failures can refuse admission.
Source: `handleDefer`, the deferred dispatch path, and
`src/daemon/helix/schedule_snapshot.zig`.

## UNFURL

`UNFURL ON|OFF|<https-url>` requires registration, the server's `unfurl_enabled`
flag, and per-client opt-in. The flag defaults off and is currently an internal
server configuration field rather than a documented TOML parser option. Without
ON, URL requests return `client refused`; OFF withdraws that opt-in. The fetch is
bounded, HTTPS-only, with no cookie jar or Cookie header; private/link-local/
loopback destinations are refused before connection. A successful response is a
NOTICE with title/description/image fields, not a trusted executable preview.
Source: `handleUnfurl`, `resolveUnfurlAddress`, `unfurlBody` and
`src/daemon/unfurl.zig`.

## APPEAL

`APPEAL :<text>` files a bounded appeal keyed by the connection's observed host
(or nick fallback), subject to the repeat window; it does not require joining a
channel. `APPEAL LIST` and `APPEAL ANSWER <id> :<text>` are operator-only, and
answers are audited. Filing does not remove a ban or authenticate an account.
Although the registry marks APPEAL `.any`, connection admission still determines
whether a client can reach the handler; a hard-rejected socket cannot submit it.
Source: `handleAppeal`, `src/daemon/appeal.zig`.

## CHALLENGE

Operator configuration forms are `CHALLENGE METHOD pow|question` and
`CHALLENGE QUESTION <question> :<answer>`; they require the server challenge
feature. An unregistered held client uses `CHALLENGE <answer>` on the explicit
pre-registration route. Success can release the welcome hold; it does not log
into an account. Failed attempts incur the handler's retry delay. The registered
registry entry is operator-only, so it does not expose an ordinary post-login
client challenge API. `challenge_enabled` is currently an internal server field,
not an accepted TOML option. Source: `handleChallenge`, `processLiveLine`,
`src/daemon/challenge.zig`.

## HOLD

`HOLD RELEASE|DROP <#channel> <nick>` is operator-only. DROP discards that member's
held first-message entries. RELEASE renders the retained bodies to the local
channel and records them through the history helper. This administrative path
must not be described as a MESSAGE_V2 transactional exact-once publication or a
mesh-wide durable queue. The first-message hold mechanism is separate from a
normal accepted message. Source: `handleHold`, `src/daemon/first_hold.zig`.

## QUARANTINE

`QUARANTINE <nick> <#channel> :<reason>` is operator-only. It resolves a live
local target, parts the target from other channels and joins the quarantine
channel, then records the reason in the operator audit. This sequence is not an
atomic cross-channel transaction: a later operation can fail after earlier parts.
Source: `handleQuarantine`.

## ABUSE

`ABUSE <nick>` is operator-only and explains current in-memory throttle, shun,
DNSBL and reputation state for a live connection. It is a diagnostic view rather
than a permanent moderation verdict or an account-wide history.
Source: `handleAbuse` and [oper_cmd.zig](../../../src/daemon/oper_cmd.zig).

## Verification and lifetime

Use focused server/module tests through [the testing guide](../../guide/testing.md).
The presence of a leaf store or snapshot codec does not imply cold-restart
persistence. Check the actual store adapter and Helix capture/adopt paths before
making an automation durability promise. This reference describes the source
surface; live operational enablement is deployment-specific.
