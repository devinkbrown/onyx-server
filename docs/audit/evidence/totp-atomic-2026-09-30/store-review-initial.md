**Block — HIGH: checksum-valid malformed batch envelopes can be silently discarded at EOF.**

- **Evidence:** The format guard sets `batch_format_required` at [store.zig:1103](/home/kain/onyx-server/src/daemon/store.zig:1103), but only outer kind `0xFB` enters strict batch decoding. Other kinds reach the legacy EOF-tolerance branch at [store.zig:1124](/home/kain/onyx-server/src/daemon/store.zig:1124). Open then truncates the rejected record at [store.zig:351](/home/kain/onyx-server/src/daemon/store.zig:351).
- **Counterexample:** Commit the policy batch successfully; change its outer payload kind from `0xFB` to `0xFF`, recompute its checksum, and reopen. The intact guard is accepted, `UnknownRecordKind` is swallowed at EOF, and the entire synced batch is truncated. Open succeeds with the previous policy rows.
- **Impact:** A fully present, checksum-valid malformed envelope restores previous durable security state instead of failing closed.
- **Fix:** Once the batch format guard applies, propagate structural decoding errors even at EOF; retain recovery for physically torn or checksum-invalid tails.
- **Regression test:** Add an outer-kind corruption case to [store.zig:2993](/home/kain/onyx-server/src/daemon/store.zig:2993). Require `UnknownRecordKind` and byte-identical WAL after failed ordinary and read-only opens.

Static review against `95f75e03`; no edits or tests. SCRAM copying is explicitly forbidden by documentation, but Zig does not enforce single ownership. Production forced-reset lock ordering and auth poison consumers remain outside this review.