# Static range inspectors and the canonical Git original

At `599891304e83e853ec723dc1417550bef4e1c074`, the documented command
`control_flow.py reconstruction/base/original.so --start 0x14f4e0 --size 13224`
fails in a `core.symlinks=false` checkout. Git stores the tracked symlink as the
40-byte text `../../evidence/original/pump/deployed.so`, which the inspector tries
to parse as an ELF. `stack_access.py` has the same failure on either input.

Both inspectors now reuse the existing `original_input.resolve_original`
helper, as the scorer and window tools already do. This admits only the exact
canonical Git link payload, preserves ordinary files and native symlinks, and
keeps the report hash bound to the captured ELF bytes. Decoder, range admission,
report publication, scoring and captured inputs are unchanged.

The resolver and its narrow admission policy come from
[miracle2044's PR #2111](https://github.com/lalalune/pumpfun-source/pull/2111).
This follow-up integrates the two remaining range inspectors; it does not claim
the resolver or original Git-pointer diagnosis as new work.

## Actual before and after

The probe makes real local shared sparse Git clones, sets `core.symlinks` before
checkout, and reads the tracked original plus the unchanged captured Pump ELF.
It exercises native symlink and materialized-link checkouts on macOS. The source
revision is fixed; the after run overlays only the two complete changed production
modules, recording their hashes. No input ELF or instruction is synthesized.

Each run contains twelve primary CLI invocations:

- Two direct captured-ELF controls per checkout.
- The canonical pointer through CFG, stack original input, stack candidate input,
  and both stack inputs, in each checkout.

Before, the four materialized-pointer invocations exit 2 without a report. After,
all four exit 0 and produce stdout identical to the direct ELF controls. The
native-link controls are identical before/after too. The CFG includes 1,602
logical instructions from the documented 13,224-byte range. Its binary hash is
`7a19affaa2c6187e04a5fe0ea298cee81fa5eb8c24cfcc30d85f615e89f7b02d`.

Additional controls exercise a regular dereferenced original copy, six arbitrary
text rejections, three occupied CFG report destinations, and a missing captured
target. The occupied destinations are the pointer, captured ELF and an unrelated
prior report; all remain byte-identical. Before, these publication controls use
the direct ELF; after, they use the newly supported canonical pointer. The stack
tool writes only stdout and has no report-publication contract.

The resolver still refuses a link payload with an added newline, another program
name, or an arbitrary relative pathname. This is not general text-path support.

## Reproduce

From a Git checkout with the pinned Python requirements installed:

```sh
python -B research/static-range-git-original-20261101/reproduce.py \
  --checkout . --revision 599891304e83e853ec723dc1417550bef4e1c074 \
  --expect base --output work/static-range-before.json
python -B research/static-range-git-original-20261101/reproduce.py \
  --checkout . --expect fixed --output work/static-range-after.json
```

The base command requires its revision in local Git history. The fixed command
reads working source bytes and runs in CI. Both create and delete only owned
temporary clones, with no network access or compiler/VM invocation. Native-link
controls are skipped only if the host cannot create symlinks; the materialized
Git checkout regression always runs. This is actual `core.symlinks=false`
behavior on macOS, not a claim of native Windows validation.

[results.json](results.json) contains the source-bound before/after receipts.
No new program reconstruction, behavioral-equivalence, or security claim follows
from these static diagnostics.
