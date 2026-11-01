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

## Same reader transition in both roadmap diagnostics

A follow-up audit at PR head `6ba22e69c608ecfc90e6bece310557fec7c5786e`
found two more maintained consumers of that same reader transition:
`roadmap-stable-attribution` and `defined-dynamic-calls`. Their documented CLIs
and active CI tests fail before analysis because they still admit reader digest
`b00c2c491dce839aba97b19fd9007da5eaa99902968d88e8c44bb071bb0c9c1c`.
Both bindings now admit the already reviewed current digest
`d3b57510531d7977110e73474cf89310b68bf6705d134ffb3bc759e18d30bedd`.
The exact reader transition is `dd746bd9579d20a6b60e69467fc1c0c5627bdf2a`,
integrated through [#3821](https://github.com/lalalune/pumpfun-source/pull/3821).
The entire diff is the relocation section/entry-width/linked-symbol-table
validation and name resolution described above. No later or unmerged helper
versions are admitted.

These two fixed-pin updates follow the same diagnostics' reviewed transitions
in [#2468](https://github.com/lalalune/pumpfun-source/pull/2468) and
[#2988](https://github.com/lalalune/pumpfun-source/pull/2988). Their algorithms,
other source pins, archived research packet and captured bytes stay unchanged.
The earlier analysis-retention helper allowlists and evidence in this packet
also remain unchanged. This is a grouped follow-up to the same helper review.

`roadmap_probe.py` runs both complete diagnostic CLIs in owned LF/CRLF reader
trees on the retained Pump, AMM and Mayhem captures. Four current-reader calls
fail at the old bindings; all four pass with the reviewed bindings. Optional
controls run the exact previous admitted reader with the exact previous
wrappers: all seven semantic report files per diagnostic are byte-identical
to the current-reader reports. Only reader/adapter provenance and manifest
hashes change. Generated verifiers pass. The defined-call diagnostic retains
269/173/133 external calls and its three internal `custom_panic` graph edges.
Stable attribution retains its existing historical call-classification limits;
this follow-up changes no diagnostic semantics or historical frontier claims.

Four occupied packets survive rejected reruns, and ten independent changed
source cases remain rejected. Input and source hashes are checked after the
actual runs. Raw CRLF hashes are retained in the reports; the previous reader's
reviewed digest is identified separately as its LF-normalized source identity.

```sh
python -B research/analysis-wrapper-rebind-20261101/roadmap_probe.py --checkout . --expect base --revision 6ba22e69c608ecfc90e6bece310557fec7c5786e --prior-reader --output work/roadmap-reader-before.json
python -B research/analysis-wrapper-rebind-20261101/roadmap_probe.py --checkout . --expect fixed --prior-reader --output work/roadmap-reader-after.json
python -B reconstruction/diagnostics/roadmap-stable-attribution/test_generate.py
python -B reconstruction/diagnostics/roadmap-stable-attribution/test_reader_binding.py
python -B reconstruction/diagnostics/defined-dynamic-calls/test_generate.py
```

Use fresh output names. `roadmap-results.json` retains both complete proof
results. The CI command omits `--revision` and `--prior-reader`, so it requires
only the current checkout, including in a shallow clone. No compiler, VM or
native program execution occurs. LF/CRLF controls run on the same host; they do
not claim native Windows validation.
