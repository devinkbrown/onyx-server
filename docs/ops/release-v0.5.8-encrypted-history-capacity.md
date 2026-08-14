# v0.5.8 encrypted-room history capacity follow-up

**Status:** source-staged; not production-verified until the deployment record below is completed.

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

Fill only after both nodes are upgraded and independently verified:

- Artifact SHA-256: pending
- Local node banner and service state: pending
- `ircx.us` node banner and service state: pending
- Secured mesh health: pending
- Live maximum-envelope history proof: pending
