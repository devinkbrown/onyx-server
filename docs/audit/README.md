# Audit archive index

Point-in-time audit, benchmark, and release-evidence records. Everything here
is preserved as evidence custody: files are **not** rewritten after the fact.
A short superseded banner at the top of a file only points to later state; the
body remains the dated record. Current source/fleet truth lives in the
[docs hub](../README.md) and [production paths](../ops/onyx-server-paths.md).

## Reading order for current status

1. [production paths](../ops/onyx-server-paths.md) — verified fleet baseline.
2. [full-record review (2026-10-02)](full-record-review-2026-10-02.md) — the
   largest custody review (3,678 entries), bannered as a 2026-10-02 snapshot.
3. [mesh presence chronology (2026-10-01)](mesh-presence-2026-10-01.md) with
   its [evidence index](evidence/mesh-presence-2026-10-01/README.md).
4. Latest release receipts: `mesh-record-carry-2026-10-23.md`,
   `nickname-logging-helix-2026-10-23.md`, and the 2026-11-01 roll recorded in
   production paths.

## Known byte-identical duplicates (chain custody, not independent reviews)

- `full-record-review-2026-10-02.md` ==
  `evidence/mesh-presence-2026-10-01/record-review-21--098--record-21-root-report-after.md`
  (md5 `4a0907ce99ebd967699ac76cfb78a7b0`).
- `evidence/mesh-presence-2026-10-01/record-review-20--099-*.md` ==
  `record-review-21--097--record-21-root-report-before.md`
  (md5 `ffe4f390d3d5dfb89112684165d45519`; after N = before N+1).

Both copies are preserved deliberately; do not cite them as two independent
corroborations.
