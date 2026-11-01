# Permanent session-fence retirement

> **Superseded / historical — preserved as evidence.** This document is a point-in-time record and does not describe the current source or fleet. Current truth: [docs hub](../README.md) and [production paths](../ops/onyx-server-paths.md). Do not execute it as a current procedure.


Candidate implementation with bounded Linux acceptance; the complete mesh
retirement transition remains unaccepted.

Permanent logical-session denial must survive removal of its original signing
node from the active mesh. Active-roster-only verification would reject its
valid retained facts after removal. The candidate adds record-scoped pins for
those facts while keeping active authority separate. The denial cannot be
deleted or expired to permit the transition.

## Explicit authority

Add a bounded `[[mesh.retired_session_group_fences]]` configuration list. Each
entry contains exactly:

- `group_key`: the 32-byte digest rendered in the existing durable namespace
  key returned by `session_group_revoke_durable.keyFor(token)`;
- `issuer_key`: the original 32-byte signing public key;
- `fact_digest`: domain-separated BLAKE3 over the exact canonical signed
  GROUP_REVOKE operation bytes, including its signature.

All three fields use canonical lowercase 64-hex encoding. The digest domain is
`onyx-session-group-revoke-retirement-v1` followed by one NUL byte. A pin authorizes that exact verified
denial fact. It conveys no authority to create a different denial, join a
peer, publish inventory, reclaim a session, renew a lease or issue coverage
receipts. Active membership, activation epochs and ACK8/ACK9 coverage continue
to use the active full roster exclusively.

Validate and own the list through the existing configuration parser and loader.
Reject malformed fields, duplicate grants, unknown fields and counts above the
permanent fence bound (currently 4096 total grants). Sort validated grants for
bounded lookup; derive required groups from that same list. Do not build a
second mutable authority registry. Multiple exact facts can be alternatives
for one group because concurrent authorized origins can retain different
immutable first facts.

## Verification and completeness

Extend the durable adapter with an optional record-scoped retired-authority
callback receiving the verified issuer, origin, group-key digest and exact
fact digest. Canonical decode, signature validation, origin/key binding and
namespace-key binding precede the trust decision. Current active authority or
an exact configured grant can authorize a fact. No blanket retired-key trust
or timestamp cutoff is introduced: the signed operation has no authenticated
retirement epoch or former-roster commitment.

Use this fence-only decision consistently for cold restoration, retained Helix
verification and replay of byte-identical old GROUP_REVOKE facts. Incoming
replay invokes it inside operation-4 verification only; it must never become
a generic incoming-frame or peer-trust predicate. Checkpoint
encoding and signed wire bytes remain unchanged. Missing or conflicting facts
abort adoption transactionally.

Every configured group requires at least one verified durable denial before
cold activation. Alternative grants for that group do not each require a
separate local record. A validated active denial for the same durable group
also establishes denial. Validate this coverage in detached staging before
publishing the restored Store. Strict staged Helix adoption must independently
check the same required-group coverage, including configured groups absent
from the database; checking only database-to-checkpoint inclusion is
insufficient. Pins alone cannot reconstruct a private token
or install a denial; a new node must receive the original private durable
records through the existing private provisioning process before activation.

## Export and transition

Provide a read-only export operation with an explicit currently active issuer
selector. Verify every durable namespace record using current authority or
already configured exact grants, then emit only the selected active issuer's
group/key/digest grants. Prior retired issuers need not become active again.
Never emit tokens, account names, original signed records or credential-bearing
diagnostics. Do not rewrite the database, re-sign facts or garbage-collect
permanent denials. Bound exported records and output by the same grant limit.
Validate one stable database cut and prepare the entire bounded output before
emitting any bytes. A late invalid record or allocation failure must not
produce a usable-looking partial export.
Publish the accepted export to an explicit create-only, owner-private atomic
file using the existing publication primitives. Stdout carries a bounded
completion summary and artifact digest, not a partially writable policy
fragment. A failed file write or sync leaves no published export.

Operators stage the union of required groups and alternative facts across the
nodes, provision private records where needed, and validate each candidate
configuration before retiring the issuer. The existing active-roster Helix
contract requires the same epoch and roster digest across handoff; this feature
must preserve that restriction. An active-roster change needs its separately
accepted maintenance transition.
The final export needs a quiesced issuer and stable private durable state:
no new fact may be signed between that final cut and retirement. "Currently
active" selects configuration authority; its process can be stopped during
that maintenance window. Live-state export without this transition is a
preview, not proof of a complete retirement baseline. Configuration read limits
must accommodate a maximum-size canonical export plus the active roster;
rejecting a truncated or oversized candidate remains mandatory.

## Candidate offline command

The Linux candidate implements:

```sh
onyx-server session-fences export /private/candidate.toml \
  --baseline /private/quiesced-baseline \
  --issuer <currently-active-64-lowercase-hex-public-key> \
  --output /private/new-retired-facts.toml
```

`--wal-name <basename>` optionally replaces `accounts.wal`. The baseline must
be an owner-held, mode-0500 directory containing a mode-0400 regular WAL and,
if present, its mode-0400 `.snap` companion. Symlinks, additional hard links,
wrong ownership, writable source files and an existing writer are refused.
Use a trusted private copy prepared after quiescing the issuer; this command
neither stops a service nor establishes that all copies of a key are retired.

The command holds file leases and verifies descriptor/path identity through
publication. Separately owned real-time lease notifications preserve Zig's
I/O cancellation signal; `F_GETLEASE` also detects a break when its notification
is discarded. Unsupported lease facilities fail closed. This is dedicated
offline tooling, not a live database reader.

The output is a new mode-0600 file containing only canonical policy grants.
Existing output is never replaced. Stdout contains the grant count, SHA-256
and a fixed source label. The command syncs file contents before publication;
it does not establish parent-directory crash durability or defeat a hostile
owner changing state in the validation/publication interval. Configuration and
private baseline custody remain operator responsibilities.

Current native acceptance covers ten empty-baseline controls and five
nonempty signed-fact cases. The latter uses production-written WALs, exports
only two selected active-issuer facts while retaining an exact prior-retired
pin, and refuses missing required groups, altered retired facts, new retired
signatures and selecting a retired issuer. Both artifact hashes are bound to
the evidence; source WAL bytes remain unchanged. The complete multi-node
retirement journey below remains a separate gate.

## Required acceptance

Prove canonical pin export/import, composable repeated retirement, alternative
first facts for one group, and missing-group rejection. Reject altered wire,
wrong signer/group/account, unknown pins and new signatures from a retired key.
Prove pins grant no AKE, inventory, lease, reclaim or ACK authority. Exercise
allocation failures through parse, detached cold restore and Helix adoption;
failure preserves prior checkpoint bytes, attachments and listener ownership.
Use real nodes to retain a denial, export and stage pins, retire its issuer,
cold-start the remaining node and reject resume of the denied group. Add a new
node only after its required private-denial baseline is verified. Preserve the
active-roster hot-upgrade restriction and unrelated sessions throughout.
Include strict Helix adoption where both the database and checkpoint omit a
configured required group, alternatives A/B with only one local immutable
first fact, a newly signed operation from the same retired key for an existing
token/account, and retired-key ACK8/ACK9 rejection.
