# Re-admit reviewed current analysis helpers

Tested base: `9bd38c7d5a4684b647ab59fc8942ed56e990e3b3`.

The maintained `research/tooling-analysis-output-retention-20261029/generate.py`
CLI refuses every current captured-program request with `Unreviewed analysis
helper: scripts/analyze_program.py`. Its existing four-test CI suite has two
errors. The direct analyzer still succeeds, so the failure is the wrapper's
stale source admission rather than missing captures or a failed decoder.

This continues the current-helper review policy used by
[#3636](https://github.com/lalalune/pumpfun-source/pull/3636), preserving every
previously accepted hash. It admits five additional fixed hashes; it does not
derive accepted hashes from the input during execution.

The complete intervening source changes from the last admitted LF source at
`9120883a957d7d9b2cab6140f66fb5bc9e6774d5` are:

- `analyze_program.py`: [#3806](https://github.com/lalalune/pumpfun-source/pull/3806)
  counts all ELF relocations and separately publishes the unchanged text-window
  subtotal, with matching README labels. No generation or publication code changed.
- `window_elf_reader.py`: [#3782](https://github.com/lalalune/pumpfun-source/pull/3782)
  checks relocation section type/entry width, linked symbol-table identity and
  symbol-index bounds, and selects symbol names from that linked table. Captured
  window, call and relocation values remain consistent with the direct analyzer.
- `deep_disassembly.py`: unchanged LF bytes; only the equivalent CRLF identity
  is added to complete the wrapper's documented line-ending support.

Exact old/current helper hashes are in `source-review.json`. The fresh source
review changes only the active wrapper's allowlists. Prior source versions,
captured binaries and historical generated packets remain unchanged.

`probe.py` runs the actual direct analyzer on all four original captures and
compares every file of the wrapped packet. It repeats the wrapper in an owned
CRLF helper tree on the same host, pointing to the same read-only captures.
Before the change all eight wrapper cases fail before publication. Afterward all
eight publish exactly the same eight files as direct execution, and their
generated verifiers pass. The reports retain these full/text relocation counts:

| Program | Windows | ELF relocations | Text-window relocations |
| --- | ---: | ---: | ---: |
| Pump | 1,035 | 6,147 | 5,557 |
| AMM | 785 | 4,399 | 3,904 |
| Fees | 585 | 2,748 | 2,369 |
| Mayhem | 441 | 2,548 | 2,117 |

The fixed proof also checks all eight completed packets survive a rejected
second-program request, six independent changed-helper cases fail before
generation, and a missing capture leaves neither final output nor staging.
These are real static CLI runs, with no mocked analyzer or fabricated ELF.

From the repository root, using the pinned Python requirements:

```sh
python -B research/analysis-wrapper-rebind-20261101/probe.py --checkout . --expect fixed --output work/analysis-wrapper-rebind.json
python -B research/tooling-analysis-output-retention-20261029/test_generate.py
```

For an independent before run, use the same probe against a clean tested-base
checkout with `--expect base` and a fresh output filename. `results.json` retains
the original before/after observations; later runs require their own bindings.

This proves current-source admission, static packet preservation and same-host
LF/CRLF equivalence. It does not claim Windows execution, a source rebuild, new
VM comparisons, reconstruction gains or program safety.
