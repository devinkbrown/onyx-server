# Persistence and recovery

Onyx Server uses OroStore, an embedded typed key/value store with checksummed
write-ahead records, snapshots and a bounded recent-mutation feed. It needs no
separate database service. The public facade is `src/daemon/store.zig`; its
implementation lives in `src/daemon/store/`.

## Account store and paths

Configure the persistent account/service store explicitly:

```toml
[sasl]
enabled = true
account_db = "/var/lib/onyx-server/accounts.wal"

[storage]
max_record_bytes = 16777216
max_wal_bytes = 268435456
changefeed_capacity = 64
```

Relative paths resolve from the daemon's working directory. The supervisor
kits default to private `/var/lib/onyx-server`; custom deployments must preserve
their actual working directory and identity. Keep the containing directory and
files private. Windows additionally validates native private-directory and
file custody; see [Windows operation](windows.md).

For `accounts.wal`, the store replays `accounts.wal.snap` and then the WAL,
checking snapshot coverage and WAL epoch identity. Preserve this pair together.
Do not mix a snapshot from one cut with an unrelated log, copy a running mutable
pair as a coherent backup, or restore an old database merely to roll back an
executable. A previously issued durable account token and an in-memory exact
attachment token have different recovery boundaries.

## Write and compaction boundaries

Prepared writes reserve fallible resources before the durable publication cut.
A successful mutation writes and syncs its WAL record before publishing the
in-memory result. Ambiguous write/sync failures poison the writer instead of
pretending the mutation was never accepted. Do not repair a poisoned store by
continuing normal writes; preserve evidence and use the verified recovery path.

`snapshotAndTruncate` publishes a complete synced snapshot and rotates the WAL
under epoch/coverage checks on native POSIX. Windows has its own private-file
and held-descriptor checks. The method name does not imply that a bare manual
truncate is a supported compaction procedure. Cold replay can repair an allowed
incomplete final WAL tail; malformed interior records or mismatched coverage
are rejected.

## Families and limits

The typed families are `accounts`, `nicks`, `chanregs`, `bans`, `memos`, `vhosts`,
`props` and `history`. The changefeed records a sequence, family, mutation kind,
key and optional value; it is bounded recent state, not an unlimited audit log.

The daemon's typed configuration parser accepts and projects `[storage]` into
the actual opened store:

| Setting | Default | Accepted range |
| --- | --- | --- |
| `max_record_bytes` | 16 MiB | 65,536–268,435,456 bytes |
| `max_wal_bytes` | 256 MiB | 1,048,576–4,294,967,296 bytes |
| `changefeed_capacity` | 64 | 8–4,096 entries |

These are admission/replay ceilings, not preallocated disk capacity. Retain
headroom for the largest supported atomic operation and use the same validated
limits when reopening an existing store.

## Backup and restore

Use the configured `[backup]` workflow and its manifest to capture the supported
account-store families. Check included and excluded scope before using it for
recovery. Run an offline restore drill into a fresh private scratch directory:

```sh
onyx-server --restore-drill /private/backup --into /private/new-restore-drill
```

The drill validates the reported backup scope and reopens the restored store;
it does not start a daemon or prove complete installation recovery. Preserve
node identity, cloak/TLS keys, config, environment references and other feature
stores separately. In particular, active identity meshes require a configured
`mesh.presence_store_path`; guest-presence storage and MESSAGE_V2's in-memory
custody checkpoints are separate from the account WAL. A cold stop drops live
TCP attachments and can lose unsettled custody. Follow the [release runbook](../RUNBOOK.md)
and verify real token recovery, client participation and mesh convergence.

Source of truth: `src/daemon/store/contracts.zig`, `store/engine.zig`,
`store/checkpoint.zig`, `store/native_files.zig`, `config_format.zig`,
`src/main.zig`, and [the reference configuration](../../etc/onyx-server.reference.toml).
