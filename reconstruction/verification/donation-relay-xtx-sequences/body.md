# Donation Relay: pin cross-transaction sequence behavior

## What this adds

A new additive verification package,
`reconstruction/verification/donation-relay-xtx-sequences`, that extends
the merged `donation-relay-stateful` packet without modifying it. The
stateful packet submits one instruction per transaction; this packet
submits the sequence shapes real callers produce and the stateful packet
does not declare — 7 cases / 14 signed transactions:

- two donations in ONE transaction, and three in ONE transaction
  (debouncer totals 3,000,000 and 600 pinned);
- success then failure in ONE transaction: whole-transaction rollback —
  no epoch/debouncer account created, source keeps all 10,000,000;
- fail (`Custom(6009)`) → successful retries across transactions, and a
  success / failure / success sandwich (totals 3,000,000 and 1,000);
- a rejected epoch close (`Custom(2012)`, non-production signer)
  interleaved between two donations — donations keep working after it;
- a zero donation after a nonzero one (total unchanged at 1,000,000).

It reuses the stateful package's fixture, pinned ELFs, and its own
`Pair.compare_rows` witness, and additionally pins the original side's
per-step errors and decoded final state per case, plus a byte-identical
non-fee rollback requirement for every failed step. Both negative
controls from the stateful idiom are reported per run (mutated step
replayed through the comparison; corrupted expected debouncer total
replayed through the expectation check) and must be detected.

## Verification

Built the candidate with the package's `build_candidate.sh` (pinned
v1.44 platform-tools, locked graph, offline) and ran the producer
end-to-end in this environment:

- 7 cases, 14 transactions, 7 matching, 0 different;
- negative control detected; expected-state control detected;
- all 14 transaction signatures verified and unique;
- unit tests: `test_sequences.py` (case declarations, expectation-check
  negative controls, shared-witness controls) and
  `test_output_refusal.py` pass; both are wired into `verify.yml`
  alongside the stateful packet's tests.

No program source changes, so no score.py gate applies. The authority
boundary is unchanged from the stateful packet: the production relayer
key is not retained, so relayer-only success families remain unsupported
fixtures, not matches.

Made via @slopdotcash
Authored with AI assistance (Meta Muse Spark)
