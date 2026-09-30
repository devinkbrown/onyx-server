# Initial auth review

Verdict: Block, HIGH. Reviewer `/root/auth_services_review`, read-only.

The old backfill releases its SCRAM lock before loading and importing a durable
record. The old Services loader returns a borrowed salt without a Services lock.
A cold lookup can capture old credentials, then a forced reset commits and
publishes new credentials, then the delayed lookup overwrites the new cache with
the old tuple. The durable replacement can also free the borrowed salt before
its copy into the cache.

Fix direction: invoke a publication callback outside the SCRAM lock and hold the
Services shared lock through durable decoding and destination import. This
retains Services before SCRAM lock ordering and serializes loading with reset.
Test the actual loader paused during import while a reset waits; verify new
SHA-256 and SHA-512 credentials, revoked token authority, and cold reopen.
