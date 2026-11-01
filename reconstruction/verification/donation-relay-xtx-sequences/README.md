# Donation Relay cross-transaction sequence differential

This package extends `reconstruction/verification/donation-relay-stateful`
without modifying it. The stateful package submits exactly one instruction
per signed transaction; real callers batch instructions and retry across
transactions, so this package reuses its fixture, its pinned ELFs and its
`Pair.compare_rows` witness to submit multi-instruction transactions and
multi-transaction sequences.

## Coverage

Seven fresh stateful cases / fourteen signed transactions, none of which
the stateful package declares:

- two donations in one transaction (1,000,000 then 2,000,000), ending at a
  3,000,000 debouncer total;
- three donations in one transaction (100, 200, 300), ending at 600;
- a successful donation followed by a failing donation in one transaction:
  the transaction fails with `Custom(6009)` and rolls back whole — no epoch
  or debouncer account is created and the source keeps all 10,000,000;
- a failing transaction (`Custom(6009)`) followed by two successful retry
  transactions in later transactions, ending at 3,000,000;
- success, failure, success across three transactions, ending at 1,000;
- a donation, an epoch-close attempt signed by a non-production authority
  (rejected, `Custom(2012)`), then another donation, ending at 1,000 —
  donations keep working after the rejected close;
- a zero donation after a 1,000,000 donation, leaving the total unchanged.

Every step compares the exact error, relevant logs, event log records,
inner instructions, return data, verified transaction signature, lamports,
owners, data lengths, data hashes and complete bytes of watched accounts,
exactly as the stateful package does. Each case additionally pins the
original side's per-step errors and decoded final state (epoch, debouncer
total and state, source and destination token balances), and requires
every failed step to leave all non-fee accounts byte-identical, so a
partial intra-transaction rollback is a mismatch, not a pass. Two negative
controls are reported with every run: a mutated recorded step replayed
through the case comparison, and a corrupted expected debouncer total
replayed through the expectation check; both must be detected. The final
report also requires every logical step to have a verified, unique
transaction signature.

## Honest coverage boundary

The authority boundary is the stateful package's: the production relayer
`RLYRf96HAJSbbXCNS6ibQYnkxtb6kbfuFxqEkm9oQUc` private key is not retained,
LiteSVM signature verification is enabled, and no signer bit is injected.
Successful whitelist update, epoch close, distribution, next-epoch
admission and Jupiter paths remain **unsupported fixtures**, not matches;
the close attempt in the interleaved case executes only its signed
authority rejection path, as in the stateful package.

## Build and run

The build is the stateful package's: the repository's pinned macOS arm64
platform-tools v1.44 and the locked dependency graph. Populate the Cargo
cache once with `cargo fetch --locked`; the build itself is offline.

```sh
out=$(mktemp -d)
reconstruction/verification/donation-relay-xtx-sequences/build_candidate.sh "$PWD" "$out"
python3 reconstruction/verification/donation-relay-xtx-sequences/producer.py \
  --candidate "$out/donation_relay_candidate.so" \
  --output "$out/report.json"
python3 -m unittest \
  reconstruction/verification/donation-relay-xtx-sequences/test_sequences.py \
  reconstruction/verification/donation-relay-xtx-sequences/test_output_refusal.py
```

As with the stateful package, this package makes runtime-behavior claims
only; it does not claim the locally built candidate has the selected
Relay's exact byte layout. The JSON report pins the original, candidate,
dependency, and complete maintained Relay source hashes, and uses the
stateful package's classifications: `equal_observed_behavior`,
`different_behavior`, `unsupported_fixture`, and a fatal infrastructure
error. Unsupported cases never contribute to the match count.
