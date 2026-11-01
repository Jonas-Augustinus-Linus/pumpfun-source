# Valid long output names in the qualification adapter

Base: `599891304e83e853ec723dc1417550bef4e1c074`.

The maintained `reconstruction/tooling/revalidation-qualification/audit.py`
CLI rejects an otherwise valid 240-character ASCII output basename with
`File name too long`. It appends `.revalidation.lock` to the complete basename;
its independent staging prefix also leaves no suffix room. The root runner's
temporary helper was already corrected in
[#3035](https://github.com/lalalune/pumpfun-source/pull/3035), which refreshed this
adapter's reviewed-source pin but did not change these two local naming paths.
This is a follow-up to that correction.

The adapter now uses a whole-character prefix of at most 64 filesystem-encoded
bytes. When truncated, it appends the complete basename's SHA-256 before the
existing lock/staging suffix. This retains separate reservations for distinct
long destinations sharing a prefix. Short names, final names, private staging
permissions, source admission and exclusive publication retain their existing
behavior. The root checker and its reviewed digest are unchanged.

## Actual CLI evidence

The probe copies the complete production adapter and its pinned root checker
into an owned temporary cohort. Its only packet payload is the unchanged
retained `.github/workflows/search-dependency.yml` (SHA-256
`16684584401a14fa4cb60c9e41416c69b217fb3f69eb4d1fc1ea2560d34e4007`). A new local
manifest binds those YAML bytes. This manifest asserts no historical build
provenance. The packet has no `verify.py`; no workflow command is executed.

Each revision runs eleven qualification CLI invocations across nine scenarios:

- Ordinary output and a valid 240-byte multibyte name publish before and after.
- The 240-character ASCII name and two distinct long names with the same prefix
  fail before and publish after. Their complete static input/result records
  and summary counts equal the ordinary output control.
- Existing directory and regular-file outputs remain unchanged and refused.
- An actual `RLIMIT_FSIZE=64` write failure leaves no destination or auxiliary
  directory; retry succeeds and the generated report verifies. Both ordinary
  and long output names exercise this failure after the fix; the old adapter
  cannot reach the write for the long name or successfully retry it.

All five unaffected scenario records are identical before and after. Every
successful output's generated JSON/hash verifier passes. Cohort inputs remain
unchanged. [results.json](results.json) retains the observations.

Five regression methods also hold a real adapter lock while invoking the CLI:
the same destination is blocked, a distinct same-prefix destination succeeds,
and releasing the lock permits retry. This is a cooperating-writer lock control,
not a claim about arbitrary competing processes. The existing workflow already
discovers `test_*.py` in this adapter directory.

```sh
python -B research/qualified-audit-output-names-20261101/probe.py --repo . \
  --revision 599891304e83e853ec723dc1417550bef4e1c074 --output work/names-before.json
python -B research/qualified-audit-output-names-20261101/probe.py --repo . \
  --output work/names-after.json
python -B reconstruction/tooling/revalidation-qualification/test_output_names.py -v
python -B -m unittest discover -s reconstruction/tooling/revalidation-qualification -p 'test_*.py'
```

Use fresh proof output paths. Tested locally on macOS with Python 3.12.13. The
write-failure control requires POSIX. No compiler, VM, native model, protocol,
captured-program execution or network service is involved. The generated audit
verifier checks only its static report files and counts; historical research
packets are not executed or rewritten.

Validation: 67 qualification tests (including the five new methods), all 253
unchanged mandatory tooling tests, and the nine retained capture checks passed.
The mandatory tooling suite includes its existing LiteSVM fixtures; the
static-only limitation above describes this public reproduction, not that
separate pre-existing suite.
