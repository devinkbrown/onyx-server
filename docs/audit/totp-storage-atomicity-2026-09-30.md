# TOTP policy and opaque token storage atomicity

Status: complete; implemented, independently reviewed, Linux and native gates pass.
No deployment or push.
Starting commit: `95f75e03`.

Before this change, `TOTP CONFIRM` activated the pending in-memory secret before
persisting it. `TOTP DISABLE` removed the live secret before persistence and
ignored storage errors. Both used best-effort token revocation, which could leave
the account's current opaque SASL token valid. A failed operation could therefore
change live authentication policy without changing the policy restored on restart.

The implemented durable cut preserves the existing raw `tot\0<account>` secret and
`T1` token records. It puts or deletes the secret and deletes
`sessiontokacct:<account>` in one prepared transaction. Token validation already
requires that account binding; an orphan `sessiontok:<hash>` row is insufficient
to authorize a login. Runtime confirmation or removal follows successful durable
commit without a fallible allocation between commit and publication.

Opaque token issuance and rotation use the same prepared transaction. Forced
password reset also changes the account password, durable SHA-256/SHA-512 SCRAM
credentials and token authority together. A prepared SCRAM cache replacement
holds its lock across the durable cut and publishes without allocation. When no
SCRAM cache is attached, reset removes any stale durable SCRAM row.

Lock order is runtime TOTP, Services, then the store prepared lane; forced reset
holds Services before the SCRAM cache. SCRAM backfill invokes its loader after
releasing its own lock. The loader holds the Services shared lock through
decoding and cache publication, so borrowed salt stays valid and a delayed load
cannot overwrite a reset's new credentials. No Services operation may acquire
the runtime TOTP lock.

| Boundary | Required outcome |
| --- | --- |
| Wrong confirmation code | Pending secret and durable policy unchanged; no success reply |
| Allocation or WAL admission failure | Previous live and durable policy retained; same confirmation code can be retried |
| Torn transaction write | No partial policy on reopen; live authentication disabled until reopen |
| Complete write followed by failed sync | Durable result treated as uncertain; no new authentication until reopen |
| Successful enable or disable | Secret policy and token authority change together; live state matches durable policy |
| Compaction and reopen | Whole transaction retained; existing raw secret and token decoding preserved |
| Older reader | Committed transaction format rejected rather than silently dropping the policy change |

This work concerns local durable account policy and opaque SASL `sst_` tokens.
Reusable mesh session credentials have their own authority and lifecycle.

STORE tests pass 113/113 in Debug and ReleaseSafe; focused Services tests pass
77/77, and all-TOTP tests pass 91/91. Native OpenBSD Debug and ReleaseSafe each
pass 170/171 selected storage/TOTP/SCRAM tests on the default 8192 KiB stack;
the one skip is the existing Linux-only same-image USR2 test. Fresh independent
store, authentication leaf and integration reviews approve the frozen source.

Existing stores are accepted by the new binary. After any prepared batch has
been committed, a mandatory format guard makes older binaries refuse the store,
including after compaction; cold downgrade to those binaries is unsupported.
Email reset still consumes its code before fallible password admission; failure
requires a new code. Existing attached clients stay attached during store poison.

Commands, complete counts, fault receipts, source/artifact hashes and review
records are in [the evidence bundle](evidence/totp-atomic-2026-09-30/README.md).

Full Linux Debug and ReleaseSafe each pass 8794/8818, 24 skips, zero failures,
8/8 steps. Named ReleaseSafe passes 1032/1036 with four skips. Named Debug
Services passes 564/564; the server retry passes 468/472 with four skips.
An initial unchanged Helix redial readiness failure and its investigation are
retained in the evidence bundle rather than omitted from the release record.
