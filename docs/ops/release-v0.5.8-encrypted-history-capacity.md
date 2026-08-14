# v0.5.8 encrypted-room history capacity follow-up

**Status:** production-verified on both nodes (2026-08-14).

## Scope

- Raise Lotus history text retention from the legacy 512-byte ceiling to the
  server's accepted 4096-byte `ONYXROOM1` envelope ceiling. This closes the gap
  where a valid encrypted room message could be delivered live but omitted from
  `CHATHISTORY`.
- Restore v1 Lotus checkpoints written with an older positive text ceiling into
  the larger current store. All other encoded capacity fields remain exact, and
  every decoded row must fit both the encoded and current ceilings.
- Keep canonical checkpoints within the concrete 64 MiB budget at admission
  time. Saturation evicts the deterministic oldest retained entry rather than
  producing an uncheckpointable state.
- Render bounded history/search/bouncer replies into an owned buffer so a valid
  aggregate replay larger than the former 32 KiB scratch buffer is not dropped.

## Compatibility and rollback boundary

The checkpoint migration is intentionally directional: the new binary accepts
older 512-byte-ceiling v1 checkpoints. Every checkpoint written by the successor
declares the 4096-byte ceiling, so an older binary rejects it even when every
retained row is short or the store is empty. Rollback therefore requires
restoring the pre-upgrade checkpoint together with the pre-upgrade binary, or
starting with explicitly empty history state. Do not perform an in-place binary
downgrade against any successor-written checkpoint.

The v1 wire framing and checksum domain are unchanged. This release does not
alter E2EEGROUP control custody, keys, or payload visibility; Lotus retains only
the opaque room envelope already admitted by the daemon policy.

## Required gates before deployment

```sh
zig fmt --check src/proto/lotus.zig src/daemon/server.zig
zig build test
zig build test -Doptimize=ReleaseSafe
```

Also prove on a staged runtime that a maximum accepted required-room envelope is
present in local and mesh `CHATHISTORY`, and that a multi-row replay over 32 KiB
is complete and correctly batch-framed.

## Deployment record

- Final source/binary version: `35598f7` / `Onyx Server 0.5.8+35598f7`.
- Artifact SHA-256:
  `ed6f2213f8458f20caec3b31567fcbbdcc4476749a23dc6fe374899729ee6a98`.
- Final-source gates: `zig fmt --check`, `zig build test`, and
  `zig build test -Doptimize=ReleaseSafe` all exited zero. The focused
  CHATHISTORY suite passed 81/81, and independent blocker review found no P0/P1.
- Local `eshmaki.me`: active with unchanged PID `828697`; the journal recorded
  the `35598f7` banner, Helix resume, six restored client connections, and the
  resumed secured link to `ircx.us`.
- Remote `ircx.us`: active with unchanged PID `1245448`; the journal recorded
  the `35598f7` banner, Helix resume, three restored TLS client connections, and
  the resumed secured link to `eshmaki.me`.
- Secured mesh: both metrics endpoints reported `links_active=1`, `peers_up=1`,
  and `partitioned=0`; Era2 acceptance and bidirectional plaintext-to-TLS guest
  chat smoke both passed.
- Live maximum-envelope proof: eight distinct exact 4096-byte `ONYXROOM1`
  messages delivered from the local node to the remote node and replayed
  completely from remote TLS in one labeled-response `CHATHISTORY` batch larger
  than 32 KiB. This also proved tagged CHATHISTORY parsing and client-only E2EE
  tag preservation.
- Rollback binaries retained on both nodes, including the pre-wave `659a7c2`
  backup and the intermediate `d50e5e7` backup from the tagged-command follow-up.

The first local `659a7c2` rollout attempt was correctly refused while session
replicas were converging; a later verified retry succeeded. No restart or PID
change was used for either final `35598f7` upgrade.
