# Type-sensitive retained Mayhem comparisons

At base `9bd38c7d5a4684b647ab59fc8942ed56e990e3b3`, the five saved-trade
verifiers compare account snapshots, CPI metadata, error values and expected
payer/rollback snapshots with Python equality. That equates JSON `false` with
`0` and integers with equal-valued floats. The producer's snapshot serialization
retains `executable` as a boolean and `rent_epoch`/`lamports` as integers.

A one-sided `rent_epoch: 0` to `false`, `executable: false` to `0`, or integer
lamports to float change is therefore accepted as equal. Symmetric after-only
changes also evade the payer and failed-transaction rollback comparisons.
Actual legacy-success CPI entries show the same problem for integer versus
floating-point `stackHeight`. The verifier publishes a successful saved-receipt
check despite the unequal typed values.

The shared comparison helper checks types recursively before comparing values.
All five readers use it at their existing JSON comparison sites. The Mayhem
executable's explicit image-hash guard, its intentional exclusion from
cross-image account parity, transaction bytes/signature checks, arithmetic,
event construction and publication behavior remain unchanged.

This follows the type-sensitive retained comparison precedent in
[#3758](https://github.com/lalalune/pumpfun-source/pull/3758) and
[#3805](https://github.com/lalalune/pumpfun-source/pull/3805), and preserves the
Mayhem selector/count and executable-snapshot admissions from
[#2250](https://github.com/lalalune/pumpfun-source/pull/2250) and
[#3296](https://github.com/lalalune/pumpfun-source/pull/3296).

## Actual saved data and source bindings

The probe invokes the production `verify_mayhem_*.py` CLI files in isolated
directories. It copies each selected verifier and the real publisher, together
with the exact source/fixture bytes already bound by the original receipt.
Historical fixture Python files are read and hashed, never imported or executed.
No verifier check, source pin or ELF pin is disabled or rebound.

- Legacy buy/sell: complete 486/396-case receipts and the genuine candidate
  `9e4e19dfb3b3fefbec13ecfc0d43ffd2ff0bea7b74ac7b2fe14126d23c79c05b` from
  `repro/mayhem/twentyfour/` at
  `b4448f7bc202063a711565b543ae4b49770def90`. The small committed fixture extracts
  keep one complete success and one complete rejection case each, with raw
  source receipt hashes, original indexes and canonical case hashes in
  `fixtures/provenance.json`. Only aggregate counts are recomputed for subsets.
- BuyV2, SellV2 and both PumpSwap directions: the four unchanged genuine signed
  rejection receipts in the existing
  `research/mayhem-v2-compressed-receipts/receipts/after-reports.tar.gz` from
  [#3535](https://github.com/lalalune/pumpfun-source/pull/3535). The committed support archive also retains the exact three differential sources
  already bound by these receipts, so later signature-check changes cannot force
  a source-pin rewrite or a historical Git lookup in CI. Their exact
  historical fixture sources come from
  `32d0ffd95e81fe31f13fc0497198f4a4175ce735`.

The full compatibility control preserves all 886 cases, including 321 legacy
successes. Every complete output dictionary is identical before and after:
1,772 signed transaction records, 642 quote/CPI and event/state checks, and
1,130 rollback checks. These are newly verified saved records, not new runtime
executions or source-equivalence evidence.

## Repeat

With the repository's pinned requirements installed:

```sh
python -B research/runtime-mayhem-typed-receipts-20261101/probe.py \
  --repo . --revision 9bd38c7d5a4684b647ab59fc8942ed56e990e3b3 --output <fresh-before>
python -B research/runtime-mayhem-typed-receipts-20261101/probe.py \
  --repo . --output <fresh-after>
python -B tests/test_mayhem_typed_receipts.py
```

Each probe runs 172 actual CLI invocations: 76 type contradictions, 12 valid
controls, and 84 existing rejection controls across plain/gzip inputs. The base
accepts all 76 contradictions; the fixed readers reject them before publication.
Changed numeric values, account data, signatures, candidate image and hashed
source are still rejected, as are input/output aliases and optimized Python.
All inputs remain unchanged and no staging files remain.

Add `--full-corpus` to either probe command to read the complete legacy reports
from the named historical Git revision and independently verify the committed
subset case hashes and candidate bytes. This requires those historical Git
objects; the normal regression test uses the committed bounded extracts and
does not need history or network access. Neither mode executes a VM.

Validation commands and exact results are in `results.json`. This fixes equality
only: equal malformed values on both sides are not generically schema-validated,
and existing truthy signature markers are unchanged. Program source, captures,
historical packets and stopped scopes are untouched.
