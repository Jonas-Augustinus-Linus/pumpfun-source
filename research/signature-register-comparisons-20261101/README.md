# Register comparisons in the maintained signature CLI

At `599891304e83e853ec723dc1417550bef4e1c074`, the current
`scripts/bytecode_signatures.py --output <packet>` command omits register-form
JEQ/JNE immediately after an offset-zero LDXDW. Its detector accepts only the
immediate forms of those same two conditions. The omitted pairs are still absent
from the per-window patterns, signatures and aggregate validation counts.

[0xJeffSun's accepted PR #994](https://github.com/lalalune/pumpfun-source/pull/994)
already identified this encoding gap in a separate research adapter. This change
integrates that accepted correction into the maintained default CLI. It does not
claim the original discovery or restore the removed adapter. One predicate adds
`0x1d` and `0x5d`; program selection, instruction boundaries, owner-field access
counts and the existing immediate comparison behavior remain unchanged.

## Actual current CLI results

The same complete CLI was run before and after on the three unchanged captured
inputs it already selects. The probe independently decodes raw instruction pairs
in every generated window, then checks the pattern, signature and summary views.

| Program | Windows | Candidate pairs before / after | Windows flagged before / after |
| --- | ---: | ---: | ---: |
| Pump | 1,035 | 52 / 75 | 36 / 46 |
| PumpSwap | 785 | 41 / 57 | 30 / 35 |
| Mayhem | 441 | 88 / 208 | 82 / 111 |

All 159 additional pairs are register JNE instructions that read the register
loaded by the preceding LDXDW. The 181 immediate pairs remain counted. No retained
register JEQ pair occurs here. Every other report field is identical, including
owner-field counts, syscall/serialization/error/token patterns, opcode signatures,
shared signatures and n-grams. Both generated packet verifiers pass, and all
capture bytes stay unchanged.

For example, Pump file offset `0xd6a8` contains
`79610000000000005d17040000000000`. The installed v1.44 official `llvm-objdump`
independently decodes it as `ldxdw r1, [r6 + 0x0]` followed by
`jne r7, r1, +0x4`. Window `0xd5d0` changes from zero candidates to one.

## Reproduce

Use the repository's pinned Python requirements and fresh output paths:

```sh
python -B research/signature-register-comparisons-20261101/probe.py --repo . \
  --revision 599891304e83e853ec723dc1417550bef4e1c074 --expect base --output work/signatures-before.json
python -B research/signature-register-comparisons-20261101/probe.py --repo . \
  --expect fixed --output work/signatures-after.json
python -B scripts/test_signature_register_comparisons.py
```

The first command requires the named local Git object. Both commands copy the
three complete production modules and captured inputs into an owned temporary
directory, execute the real CLI and generated verifier, and remove that directory.
No detector is mocked, and no input instruction or ELF is manufactured. The new
regression is included in CI and fails on the unchanged base.

`results.json` contains compact before/after receipts. Each program's
`register_witnesses_sha256` hashes the probe's complete `register_witnesses` list
using JSON with sorted keys and compact separators. The probe emits all 159 raw
witnesses. `unrelated_report_sha256` removes only the two affected per-window
validation fields and their summary/README counts; the enclosing manifest is
excluded because it necessarily hashes changed reports. The two resulting maps
are identical.

The retained token-constant and terminal-error packets use their own archived
source copies. Those inputs, receipts, manifests and verifiers remain unchanged
and their verification/tests still pass. No current-source digest binding needs
an update.

This remains an adjacency heuristic. It does not prove an Anchor discriminator,
account authorization, executed validation, runtime behavior or source equivalence.
Existing unrelated-register immediate heuristics are deliberately preserved.
No program source, scoring rule, build input, compiler, native model or VM is used
or changed by this work.
