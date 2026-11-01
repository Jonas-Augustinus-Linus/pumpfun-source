# Unambiguous saved capture and provenance fields

At tested base `599891304e83e853ec723dc1417550bef4e1c074`, the mandatory
`scripts/verify_evidence.py` CLI accepts contradictory duplicate JSON members in
capture records and upstream hash provenance. Python's default decoder silently
retains the last value. For example, prepending `"commitment":"processed"` to
the unchanged Pump capture record still prints `9 captures verified`, because
its later `"commitment":"finalized"` wins. A record containing only the wrong
commitment is already rejected.

The same problem affects a repeated program address or legacy-loader owner, an
escaped spelling of an existing key, a repeated upstream file hash, and a
repeated whole upstream hash map. This is an offline evidence-admission defect;
it does not establish a live-chain or deployed-program vulnerability.

One duplicate-aware decoder now admits both capture records and upstream
provenance before their existing value/hash checks. It rejects repeated decoded
names at every object depth, including equal repeated values. All existing
address, loader, slot, hash and captured-byte checks remain in place. This follows
the repository's duplicate-aware verification precedents
[#2105](https://github.com/lalalune/pumpfun-source/pull/2105),
[#2569](https://github.com/lalalune/pumpfun-source/pull/2569), and
[#3525](https://github.com/lalalune/pumpfun-source/pull/3525).
[RFC 8259 section 4](https://www.rfc-editor.org/rfc/rfc8259#section-4) recommends
unique object names and describes the differing behavior of consumers when
names repeat; this gate chooses explicit rejection.

## Actual CLI proof

`probe.py` copies the retained nine captures and upstream inputs into a private
temporary directory, then invokes the real CLI without mocks or source edits.
Eight duplicate-field variants run under normal Python, `-O`, `-OO`, and both
`PYTHONOPTIMIZE` settings. These 40 ambiguous inputs all pass before the fix and
all fail afterward. Five unchanged-corpus controls still pass with identical
stdout, and five unambiguous wrong-commitment controls still fail. There are 50
actual CLI invocations per revision. Every retained input byte is restored and
verified; the capture producer, original records, IDLs and binaries are untouched.

With the repository's pinned Python requirements:

```sh
python -B research/evidence-json-members-20261101/probe.py --repo . \
  --revision 599891304e83e853ec723dc1417550bef4e1c074 --output work/json-members-before.json
python -B research/evidence-json-members-20261101/probe.py --repo . \
  --output work/json-members-after.json
python -B scripts/test_capture_verification_modes.py
python -B scripts/verify_evidence.py
python -B scripts/test_tooling.py
```

Choose fresh proof output paths. The exact-base command needs the named local
Git object; the fixed command needs no Git history. `results.json` retains the
source/input identities and all before/after invocation results. The existing
capture-verification regression, already imported by the required tooling suite,
now includes the same duplicate forms in every optimization mode.

## Maintained source binding and limits

The legacy-capture-metadata packet binds the current verification script, so its
`inputs.json` and enclosing `manifest.json` receive only the reviewed source
digest update, following [#2761](https://github.com/lalalune/pumpfun-source/pull/2761).
Its capture hashes, saved observations, coverage delta, verifier, tests and
historical explanation are unchanged. The retained nine-capture observation is
rechecked, as is the maintained packet-invocation suite.

This does not add a general JSON schema, authenticate RPC responses or capture
timestamps, or change upstream JSON standards. No capture, build, model or VM
execution is performed by the proof. No source-equivalence or security-clearance
claim follows from these metadata checks.
