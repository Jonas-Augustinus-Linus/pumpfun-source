# Direct callid and inline report input preservation

At base `9bd38c7d5a4684b647ab59fc8942ed56e990e3b3`, direct diagnostic
report destinations can replace the inputs they have just analyzed. This packet
repeats the production CLIs using only disposable copies of retained inputs.

The eight before/after cases cover:

- callid JSON at the candidate path, a candidate symlink, or a candidate hardlink;
- callid JSON at the original Git link-text pointer, its resolved captured ELF,
  or the function inventory;
- parse-only inline JSON linked to the existing compiler log, using a symlink or
  hardlink.

Every base invocation exits 0 and changes its corresponding input. Every fixed
invocation exits 2 with `report destination aliases an input`, leaving all input
bytes unchanged. The fixed build entrypoint also rejects a log alias before
reaching a build; its source and work paths are absent, and no compiler is run.

Normal direct reports, repeat replacement at the same report path, and the actual
portable callid adapter continue to work. Callid retains 1,020 normalized and
1,020 bisimilar matches after four rounds; inline parsing retains two selected
remarks. The complete normal JSON payloads match before/after, excluding only the
private temporary candidate pathname from the cross-run comparison. Within each
run, portable and direct callid report bytes are identical.

## Inputs and reproduction

The candidate is the unchanged
`reconstruction/pump-main/lanes/v3-sell-payment-layout/candidate.so.gz` ELF,
decompressed SHA-256
`969811b0e0f673b693695ea651008cacd93eafa5a663dd8bec0e61d3b22d09a9`.
The original and inventory are `evidence/original/pump/deployed.so` and
`reconstruction/base/functions.tsv`. The log consists of the three authentic
compiler-produced remarks retained in
`reconstruction/harness/fixtures/inline-remarks-v144.json`; joining them with
newlines gives SHA-256
`48ceff50b0c08d0797c7bb472e00acf6d7f64aa2a04e53896d583daf22cacf7c`.
This is replay of retained log lines, not a new compiler capture.

Use the repository's pinned Python requirements from the checkout root:

```sh
python -B research/callid-inline-input-preservation-20261101/reproduce.py \
  --checkout . --revision 9bd38c7d5a4684b647ab59fc8942ed56e990e3b3 \
  --expect base --output work/callid-inline-before.json
python -B research/callid-inline-input-preservation-20261101/reproduce.py \
  --checkout . --expect fixed --output work/callid-inline-after.json
```

The base command requires that revision in local Git history. The fixed command,
also wired into CI, reads current source bytes. Both commands stage complete
production modules and private input copies in a temporary directory, use actual
subprocess CLIs without mocks, record their source/input hashes, assert the
expected outcomes, and remove their disposable cohorts. No SDK is required.
[results.json](results.json) retains the recorded exact-base/fixed receipts.

## Scope and integration

The fix reuses the existing `score_admission.report_destination` check at direct
CLI entry. It covers existing lexical, resolved-path, and inode aliases. It does
not make a late-race, atomic-publication, whole-source-tree, or library `parse()`
API guarantee. Existing report replacement remains supported. No scoring rule,
diagnostic algorithm, historical evidence, program source, or capture is changed.

[PR #3849](https://github.com/lalalune/pumpfun-source/pull/3849) owns the analogous
census CLI change; census source and its reviewed digest are excluded here.
[PR #3837](https://github.com/lalalune/pumpfun-source/pull/3837) owns dataref changes.
This fix changes only the callid entry in the portable adapter's reviewed map;
integration must preserve independently reviewed census/dataref entries and
their adapter behavior. A source change merged without its matching reviewed
digest will still be rejected by that adapter.
