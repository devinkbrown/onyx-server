# Independent integration review

Reviewer: `/root/repair_full_test_gate`, read-only source review, no source edits
or reviewer-run tests. Baseline `114e1cd4`. Final verdict: no remaining confirmed
source blocker in the bounded authenticated-account marker scope.

Traced local/remote admission, atomic durable row plus independent-clock batch
before runtime publication, original signed frontier forwarding, reserved PROP
exclusion, secured-only negotiated admission/egress, capability arrival and
reconnect/RESYNC repair, staged cold restore/unavailable latch, and both Helix
reader negotiations. Privacy assumes a consistent canonical Services account
namespace across authorized nodes. Global account ownership is a separate gap.
Guests are physical-connection memory only.

Initial HIGH: unchanged upgrade capabilities allowed an older ENTITY_PROP reader
to inherit queued/kernel/partial marker ciphertext and emit timestamp/target as
public PROP. Renegotiation cannot retract those bytes. Both current writer gates
now require `read-marker-mesh-v1` before handing over service descriptors; exact
frozen predecessor advertisements and replies retain forward compatibility.
The actual v4-only ELF regression checks queues, counters, clock, durable sequence,
signatures, and descriptors. The public upgrade refusal audit normally transfers
outer ciphertext into SendQ; the corrected fixture verifies original ciphertext
prefixes and exactly one verified audit through real secured receiver decoding.

Initial MEDIUM: outer OOM left private plaintext in the inner queue and retry
could append duplicates. Private send now validates bounded length and reserves
both queues before publication; unrelated pending work returns a retryable refusal.
The RED regression observed 319 inner bytes instead of zero. Its unchanged checks
now cover both queues, retained frontier, retry, and duplicate suppression.

The final bouncer fixture correction supplies real OroStore/Services to the custom
SASL scenario and heap-allocates Server. Actual MARKREAD commands, history-policy
checks, rewind contents and PING barrier are preserved. No production difference
or weakened assertion was found. Exact earlier source reconstruction is recorded
in `integrator-production-parity.txt`.

Reviewer inspected refusal Debug 72/72 and bouncer Debug/ReleaseSafe 74/74 logs.
Full Linux and native gate acceptance is separate root evidence. Final eight-file
source pins are recorded in `source-sha256.txt`.
