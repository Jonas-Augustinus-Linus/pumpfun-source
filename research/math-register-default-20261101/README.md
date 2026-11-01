# Accepted register-comparison analysis in the default CLI

At `599891304e83e853ec723dc1417550bef4e1c074`, the maintained
`scripts/deep_section_analysis.py` CLI still counts only immediate unsigned
comparisons after adjacent 64-bit add/subtract/multiply instructions. The
accepted correction by **happysonny1 in
[#1618](https://github.com/lalalune/pumpfun-source/pull/1618)** already counts
the register forms in a separate source-bound successor. This change integrates
that same predicate into the default five-layer report. It is a reviewed
transition of the current script, following the root-script integration in
[#2745](https://github.com/lalalune/pumpfun-source/pull/2745), not a new pattern
discovery or a change to the archived successor.

The four added forms are JGT/JGE/JLT/JLE register comparisons. Existing
immediate comparisons, adjacency, arithmetic-window admission and ranking stay
unchanged. The upstream [SBPF opcode definitions](https://github.com/anza-xyz/sbpf/blob/f754c707f99779a756978f87c9afd25eeeb3d92e/src/ebpf.rs)
define both operand forms. Pump file offset `0xd278` contains the actual pair
`1f810000000000003d61070000000000`: `sub64 r1, r8` followed by
`jge r1, r6, +7`, also covered by the accepted successor's capture test.

## Actual default-command results

`results.json` records complete baseline and current CLI runs over the same
four retained deployed ELFs, with both sets of generated packet verifiers.
The baseline is the exact Git source and three unchanged helper files, executed
from an isolated temporary directory with the retained evidence linked in.
No code substitution, mock disassembler, compiler, program or VM is executed.
The current run invokes the actual maintained entrypoint.

| Capture | Pattern candidates before | After | Windows before | After |
| --- | ---: | ---: | ---: | ---: |
| Pump | 158 | 310 | 89 | 144 |
| Pump AMM | 121 | 196 | 63 | 101 |
| Pump Fees | 119 | 187 | 74 | 98 |
| Mayhem | 92 | 293 | 36 | 74 |

These 496 additional candidates exactly match the accepted successor and an
independent class/operation/source-bit census at logical instruction boundaries.
Every other math field, window choice, order and classification is unchanged.
Layers 1–4 and the generated verifier are byte-identical. The summary and
README change only their existing candidate-window count; manifest hashes
reflect those changed files. Input bytes and all ten files in the archived
math/relocation successor packages match the baseline and remain unchanged.

The arithmetic-shift regression intentionally hashes complete current math
reports after removing only `shifts`. Its four derived report hashes therefore
need a reviewed refresh, as documented in that packet and previously performed
in [#2535](https://github.com/lalalune/pumpfun-source/pull/2535). Both old and
new values are retained here. Its capture identities, original source hash,
baseline shift totals, test code and all actual shift counts are unchanged.

## Reproduce

Use Python 3.12 with the repository requirements, on a host supporting the
existing atomic directory publication (Linux or macOS). From the repository
root, choose a fresh output filename:

```sh
python -B research/math-register-default-20261101/probe.py --output /tmp/math-default-proof.json
python -B research/math-register-default-20261101/test_verify.py
python -B reconstruction/math-register-comparisons/test_analyze.py
python -B reconstruction/relocation-text-addresses/test_analyze.py
python -B research/tooling-arithmetic-shift-counts-20261030/test_verify.py
python -B scripts/verify_evidence.py
```

The full proof needs the named baseline Git object. The CI regression needs
only the current checkout and existing archived successor, so it also works
with a shallow checkout. The proof emits hashes and bounded counts rather than
absolute local paths or duplicate ELF bytes. It checks both unchanged archived
predicates through their real CLI and their existing source admission.

## Limits and adjacent check

The report's legacy `overflow_checks` and `overflow_protected` names denote
static pattern candidates. The presence of these instructions does not establish
overflow handling, branch meaning, runtime protection, source equivalence or
security. This contribution leaves the heuristic and its existing field names
unchanged.

The adjacent LDDW check walked all nine retained captures and found 32,632
continuation slots, each with a zero opcode byte. No arithmetic or comparison
opcode was miscounted from those continuation slots in these captures; no
LDDW traversal change is made. This is a bounded negative control, not a claim
about every possible ELF. No native program or VM execution is part of this
packet.
