# Diagnose terminal straight-line fallthrough in CFG slices

The CFG CLI on main `599891304e83e853ec723dc1417550bef4e1c074` reported
success for only the first 8 bytes of the retained `admin_cto` window. The
reported successor was outside the selected range, but `diagnostics` was empty.
This fix emits `fallthrough outside function` and exits 1 for that incomplete
range. A complete instruction is not necessarily a complete function.

This follows [#2340](https://github.com/lalalune/pumpfun-source/pull/2340), which
handled branch and conditional-fallthrough boundaries. That patch is already
merged; this change covers ordinary instructions, including a complete LDDW.
Terminal calls retain their prior behavior because the decoder does not infer
whether a callee returns. This is not a whole-program validity judgment.

## Retained results

- [Before CLI JSON](before.json): exit 0, no diagnostic.
- [After CLI JSON](after.json): exit 1, boundary diagnostic at offset 0, target 8.
- [Result receipt](result.json): input/tool hashes and unchanged-window census.
- All 1,035 complete retained Pump windows have byte-for-byte equivalent
  canonical CFG JSON before/after, with zero diagnostics in both runs.
- No program source, build input or score normalization changed. No program was
  rebuilt and no new binary match is claimed.

## Public action receipt / reproduction

Run from the repository root with Python 3.12; use a fresh report path:

```sh
python -B reconstruction/harness/control_flow.py evidence/original/pump/deployed.so --start 0x22a10 --size 8 --json /tmp/cto-prefix-cfg.json
python -B -m unittest discover -s reconstruction/harness -p 'test_control_flow*.py' -v
python -B -m unittest discover -s reconstruction/harness -p 'test_diagnostic*.py' -v
python -B tests/test_control_flow_sbpf_opcodes.py
python -B scripts/verify_evidence.py
python -B scripts/test_tooling.py
```

The first command must exit 1 after this fix. It reads the preserved capture;
no VM, wallet, network request or transaction is involved. Before/after capture
SHA-256 is `7a19affaa2c6187e04a5fe0ea298cee81fa5eb8c24cfcc30d85f615e89f7b02d`.
The ordinary-instruction, LDDW, exit, loop, terminal-call, real-capture, CLI
stdout/report consistency and output-preservation cases are regression-tested.
Existing tests that supplied partial ranges now expect a boundary diagnostic;
publication and machine-admission fixtures now supply an actual exit.

The census can be independently reproduced without a compiler:

```python
import hashlib, json, sys
sys.path.insert(0, 'reconstruction/harness')
from control_flow import analyze
from score import original_windows
rows = []
for w in original_windows():
    report = analyze(w['raw'], w['start'])
    rows.append({'start': hex(w['start']), 'bytes': w['bytes'],
                 'diagnostics': report['diagnostics'],
                 'cfg_sha256': hashlib.sha256(json.dumps(report, sort_keys=True).encode()).hexdigest()})
print(len(rows), sum(bool(w['diagnostics']) for w in rows))
print(hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest())
```

Expected: `1035 0` and census digest
`8c53152ae4055924b9ce5bc331014adba3164c6a499000f30d23d10caa5d9576`.

Initial local checks exposed a sparse checkout containing only one capture and
old fixtures ending in ordinary instructions; the required retained captures
were checked out and those fixtures corrected. Windows system Python lacked
`solders`; repository checks used the existing Linux validation environment.
These setup failures are not represented as successful checks.

The first broad run on the Windows-mounted checkout also encountered Linux
`renameat2` errors and missing sparse-checkout fixtures. A separate native Linux
validation copy uses the pinned base inputs plus the changed harness files;
its initial collection needed the repository `tests` package as well. All
initial failure logs are retained locally, rather than labeled as passes.

See [validation.txt](validation.txt) for exact test commands, counts, the native
253-test run and its one missing-fixture rerun, and the workflow lint result.
