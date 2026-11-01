# Retain existing program-analysis packets

The archived `scripts/analyze_program.py` opens an existing output directory and
replaces its packet files. Reusing a Mayhem output path for Pump Fees replaces
seven files, including the summary, inventory and manifest, without a refusal.
The old 441-window Mayhem packet becomes a 585-window Pump Fees packet.

This source-bound successor runs that same analyzer in a fresh sibling staging
directory, runs its generated packet verifier, checks that the reviewed helpers
have not changed, then renames the completed directory to the requested output.
Existing files and directories are refused before generation and checked again
before publication. A failed analyzer or verifier leaves no final packet.
The frozen root scripts and prior packets remain unchanged, as required by
`scripts/README.md`.

From the repository root:

```sh
python research/tooling-analysis-output-retention-20261029/generate.py --program mayhem --output work/new-mayhem-analysis
python research/tooling-analysis-output-retention-20261029/test_generate.py
```

The wrapper accepts only the reviewed complete LF/CRLF forms of the analyzer and
ELF reader; other source changes need a new review. The four regressions use the
real captured Mayhem binary, compare all eight packet files against the archived
CLI, retain them after a rejected Pump Fees request, exercise missing-input
failure, and check helper drift and pre-existing file/directory targets.

The directory rename and final existence check do not implement a cross-process
locking protocol. Use a distinct destination per concurrent analysis. This is
packet retention and publication, not a correction to the archived decoder,
independent source reconstruction, fresh VM evidence, or security acceptance.

The current helper allowlist also covers the imported `deep_disassembly.py`
publication functions and the latest reviewed analyzer/ELF-reader LF/CRLF
forms. Its generated packets include the directory census. Prior generated
packets and the earlier accepted helper versions are retained unchanged.

## Current-helper review, 2026-11-01

On `9bd38c7d5a4684b647ab59fc8942ed56e990e3b3`, this maintained CLI and its
`analysis-packet-encoding` CI test stopped before generation because the analyzer
and ELF reader changed after the last accepted helper hashes. The re-review
admits their exact current LF/CRLF bytes and the unchanged publication helper's
current CRLF form. All earlier accepted identities stay admitted; arbitrary
edits still fail the hash check.

The analyzer change from [#3806](https://github.com/lalalune/pumpfun-source/pull/3806)
separates whole-ELF relocation totals from text-window subtotals. The reader
change from [#3782](https://github.com/lalalune/pumpfun-source/pull/3782) validates
relocation entry type/size and resolves symbols through the section's linked
symbol table. No wrapper publication logic or previously generated packet is
changed. [The new review packet](../analysis-wrapper-rebind-20261101/README.md)
records the full helper transitions, real four-program CLI comparisons, source
drift refusals, and existing-output preservation.
