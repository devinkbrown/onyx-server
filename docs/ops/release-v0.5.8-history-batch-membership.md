# v0.5.8 CHATHISTORY batch-membership follow-up

**Status:** production-verified on both nodes (2026-08-14).

## Scope

- Tag every batched CHATHISTORY and `draft/chathistory-targets` member with the
  enclosing `batch` reference while preserving `time`, `msgid`, and client-only
  E2EE tags.
- Put a labeled command's label on the existing history batch opener instead of
  nesting the history response inside a `labeled-response` batch.
- Stage and validate applicable captured batches before mutating a connection's
  SendQ. Unsafe references, mismatched membership/close framing, trailing data,
  capture overflow, and insufficient SendQ fail atomically.
- Validate batch references with the IRCv3 `[A-Za-z0-9-]` alphabet and reject
  command tokens that could inject another IRC wire line.

## Deployment record

- Source/binary version: `7933401` / `Onyx Server 0.5.8+7933401`.
- ReleaseFast artifact SHA-256:
  `609ff9eb8e143f1fadc759254dda2540d7ab2ace174088785a7c881f42cf6a2c`.
- Independent review: ship; no P0/P1 source blocker. Focused Debug and
  ReleaseSafe response-builder, labeled-response, CHATHISTORY, and maximum
  encrypted-room replay lanes passed. Direct final-byte response-builder tests
  passed in Debug and ReleaseSafe, including the complete invalid reference
  alphabet table and CRLF/space command rejection.
- `eshmaki.me`: Helix upgrade completed with unchanged PID `828697`, seven
  client connections and the secured mesh link restored.
- `ircx.us`: Helix upgrade completed with unchanged PID `1245448`, three TLS
  client connections and the secured mesh link restored.
- Both metrics endpoints reported `links_active=1`, `peers_up=1`, and
  `partitioned=0`; bidirectional local-plaintext to remote-TLS mesh chat passed.
- Live wire proof passed for local and remote replay, with and without
  `labeled-response`: exact 4096-byte `ONYXROOM1` rows carried matching batch
  tags, one history opener/close pair, and no nested labeled-response batch.
- The previous `35598f7` binary is retained on each node as an explicit backup.

No cold restart or PID change was used on either node.
